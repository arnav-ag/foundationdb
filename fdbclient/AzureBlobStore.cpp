/*
 * AzureBlobStore.cpp
 *
 * This source file is part of the FoundationDB open source project
 *
 * Copyright 2013-2026 Apple Inc. and the FoundationDB project authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "fdbclient/AzureBlobStore.h"
#include "fdbclient/IBlobStore.h"
#include "fdbclient/JSONDoc.h"
#include "fdbrpc/HTTP.h"
#include "flow/Error.h"
#include "flow/Trace.h"
#include "flow/network.h"
#include "flow/CoroUtils.h"
#include <algorithm>
#include <boost/algorithm/string.hpp>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <string>
#include "libb64/decode.h"
#include "libb64/encode.h"
#include "md5/md5.h"
#include "rapidxml/rapidxml.hpp"

constexpr const char* AZURE_API_VERSION = "2021-08-06";

// URL decode a string (for canonicalizing query parameters in signatures)
static std::string urlDecode(const std::string& encoded) {
	std::string result;
	result.reserve(encoded.size());
	for (size_t i = 0; i < encoded.size(); i++) {
		if (encoded[i] == '%' && i + 2 < encoded.size()) {
			int value;
			if (sscanf(encoded.substr(i + 1, 2).c_str(), "%x", &value) == 1) {
				result += static_cast<char>(value);
				i += 2;
			} else {
				result += encoded[i];
			}
		} else if (encoded[i] == '+') {
			result += ' ';
		} else {
			result += encoded[i];
		}
	}
	return result;
}

static std::string sha256_base64(const std::string& data) {
	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, data.c_str(), data.size());
	SHA256_Final(hash, &sha256);
	std::string hashStr(reinterpret_cast<char*>(hash), SHA256_DIGEST_LENGTH);
	std::string encoded = base64::encoder::from_string(hashStr);
	// Remove trailing newline from libb64
	if (!encoded.empty() && encoded.back() == '\n') {
		encoded.pop_back();
	}
	return encoded;
}

static void addAzureEncryptionHeaders(HTTP::Headers& headers, bool isWriteRequest) {
	// CPK mode: customer provides the encryption key
	if (!CLIENT_KNOBS->BLOBSTORE_MS_CPK_KEY.empty()) {
		std::string rawKey = base64::decoder::from_string(CLIENT_KNOBS->BLOBSTORE_MS_CPK_KEY);
		std::string keySha256 = sha256_base64(rawKey);

		headers["x-ms-encryption-key"] = CLIENT_KNOBS->BLOBSTORE_MS_CPK_KEY;
		headers["x-ms-encryption-key-sha256"] = keySha256;
		// Algorithm defaults to AES256, or use BLOBSTORE_ENCRYPTION_TYPE if set
		std::string algorithm =
		    CLIENT_KNOBS->BLOBSTORE_ENCRYPTION_TYPE.empty() ? "AES256" : CLIENT_KNOBS->BLOBSTORE_ENCRYPTION_TYPE;
		headers["x-ms-encryption-algorithm"] = algorithm;
		return;
	}

	// Encryption scope mode: Azure manages the keys within a named scope
	// Only needed on write requests - reads are transparent
	if (isWriteRequest && !CLIENT_KNOBS->BLOBSTORE_MS_ENCRYPTION_SCOPE.empty()) {
		headers["x-ms-encryption-scope"] = CLIENT_KNOBS->BLOBSTORE_MS_ENCRYPTION_SCOPE;
	}
}

static Optional<AzureBlobStoreEndpoint::Credentials> parseCredentials(Optional<StringRef> const& credString) {
	if (!credString.present()) {
		return Optional<AzureBlobStoreEndpoint::Credentials>();
	}
	StringRef c = credString.get();
	StringRef accountName = c.eat(":");
	StringRef secret = c.eat();
	return AzureBlobStoreEndpoint::Credentials{ accountName.toString(), secret.toString() };
}

// Extract storage account name from Azure hostname
// e.g. "myaccount.blob.core.windows.net" -> "myaccount"
static std::string extractAzureAccountName(const std::string& host) {
	size_t pos = host.find(".blob.");
	if (pos != std::string::npos) {
		return host.substr(0, pos);
	}
	return host;
}

AzureBlobStoreEndpoint::AzureBlobStoreEndpoint(std::string const& host,
                                               std::string const& service,
                                               Optional<std::string> const& proxyHost,
                                               Optional<std::string> const& proxyPort,
                                               Optional<StringRef> const& creds,
                                               bool sharedKeyAuth,
                                               BlobKnobs const& knobs,
                                               HTTP::Headers extraHeaders)
  : IBlobStoreEndpoint(host, service, "auto", proxyHost, proxyPort, knobs, extraHeaders),
    credentials(parseCredentials(creds)), sharedKeyAuth(sharedKeyAuth) {
	if (!credentials.present()) {
		throw backup_auth_missing();
	}
	// If accountName wasn't provided in the URL cred string (standard @host format),
	// extract it from the hostname (e.g., "myaccount" from "myaccount.blob.core.windows.net")
	if (credentials.get().accountName.empty()) {
		AzureBlobStoreEndpoint::Credentials c = credentials.get();
		c.accountName = extractAzureAccountName(host);
		credentials = c;
	}
}

bool AzureBlobStoreEndpoint::extractCredentialFields(JSONDoc& account) {
	if (!credentials.present())
		return false;
	Credentials creds = credentials.get();

	if (sharedKeyAuth) {
		std::string secret;
		if (account.tryGet("secret", secret) && !secret.empty()) {
			creds.secret = secret;
		} else {
			std::string apiKey;
			if (account.tryGet("api_key", apiKey) && !apiKey.empty()) {
				creds.secret = apiKey;
			} else {
				return false;
			}
		}
	} else {
		std::string token;
		if (account.tryGet("token", token) && !token.empty()) {
			creds.secret = token;
		} else {
			return false;
		}
	}

	credentials = creds;
	TraceEvent("AzureBlobStoreUpdatedSecret").detail("CredentialsKey", credentialFileKey());
	return true;
}

std::string AzureBlobStoreEndpoint::getResourceURL(std::string resource, std::string params) const {
	if (!params.empty())
		params.append("&");
	params.append("p=azure");
	if (sharedKeyAuth) {
		params.append("&mska=1");
	}
	return IBlobStoreEndpoint::getResourceURL(resource, params);
}

static std::string getSharedKey(const AzureBlobStoreEndpoint::Credentials& creds,
                                const std::string& verb,
                                const std::string& resource,
                                const std::string& date,
                                const HTTP::Headers& headers) {
	const std::string& accountName = creds.accountName;

	std::string canonicalResource;
	std::vector<std::pair<std::string, std::string>> params;

	size_t queryPos = resource.find('?');
	if (queryPos == std::string::npos) {
		canonicalResource = "/" + accountName + resource;
	} else {
		canonicalResource = "/" + accountName + resource.substr(0, queryPos);
		std::string queryString = resource.substr(queryPos + 1);

		size_t start = 0;
		while (start < queryString.length()) {
			size_t eq = queryString.find('=', start);
			size_t amp = queryString.find('&', start);
			if (amp == std::string::npos)
				amp = queryString.length();

			if (eq != std::string::npos && eq < amp) {
				std::string key = queryString.substr(start, eq - start);
				std::string value = queryString.substr(eq + 1, amp - eq - 1);
				// URL-decode the value for canonical resource (Azure requires decoded values in signature)
				params.push_back({ boost::to_lower_copy(key), urlDecode(value) });
			}
			start = amp + 1;
		}

		std::sort(params.begin(), params.end());
		for (const auto& p : params)
			canonicalResource += "\n" + p.first + ":" + p.second;
	}

	// canonicalize the headers, anything prefixed with x-ms-* needs to be included and sorted.
	std::string canonicalizedHeaders;
	// Rely on HTTP::Headers case insensitive sorted order.
	for (const auto& [key, val] : headers)
		if (key.starts_with("x-ms-"))
			canonicalizedHeaders += key + ":" + val + "\n";
	// build signature
	auto getHeaderOrEmpty = [&headers](const std::string& key) -> std::string {
		auto it = headers.find(key);
		return (it != headers.end()) ? it->second : "";
	};
	// Azure explicitly calls Content-Length special case to empty string in signature for zero-length content
	std::string contentLengthForSig = getHeaderOrEmpty("Content-Length");
	if (contentLengthForSig == "0")
		contentLengthForSig = "";

	std::string stringToSign = verb + "\n" + // HTTP Verb
	                           getHeaderOrEmpty("Content-Encoding") + "\n" + getHeaderOrEmpty("Content-Language") +
	                           "\n" + contentLengthForSig + "\n" + getHeaderOrEmpty("Content-MD5") + "\n" +
	                           getHeaderOrEmpty("Content-Type") + "\n" + getHeaderOrEmpty("Date") + "\n" +
	                           getHeaderOrEmpty("If-Modified-Since") + "\n" + getHeaderOrEmpty("If-Match") + "\n" +
	                           getHeaderOrEmpty("If-None-Match") + "\n" + getHeaderOrEmpty("If-Unmodified-Since") +
	                           "\n" + getHeaderOrEmpty("Range") + "\n" + canonicalizedHeaders + canonicalResource;

	std::string decodedKey = base64::decoder::from_string(creds.secret);
	unsigned char hash[SHA256_DIGEST_LENGTH];
	HMAC(EVP_sha256(),
	     decodedKey.c_str(),
	     decodedKey.length(),
	     (unsigned char*)stringToSign.c_str(),
	     stringToSign.length(),
	     hash,
	     nullptr);
	std::string signature = base64::encoder::from_string(std::string((char*)hash, SHA256_DIGEST_LENGTH));
	signature.resize(signature.size() - 1); // Remove trailing newline from libb64

	return "SharedKey " + accountName + ":" + signature;
}

void AzureBlobStoreEndpoint::setAllRequestHeaders(const std::string& verb,
                                                   const std::string& resource,
                                                   HTTP::Headers& headers,
                                                   std::string date,
                                                   std::string datestamp) {
	if (date.empty()) {
		time_t now_time = time(nullptr);
		struct tm* gmt = gmtime(&now_time);
		char dateBuf[128];
		// Azure requires x-ms-date header in RFC 1123 format
		strftime(dateBuf, sizeof(dateBuf), "%a, %d %b %Y %H:%M:%S GMT", gmt);
		date = dateBuf;
	}

	headers["x-ms-date"] = date;
	headers["x-ms-version"] = AZURE_API_VERSION;

	if (credentials.present() && !credentials.get().secret.empty()) {
		if (sharedKeyAuth) {
			headers["Authorization"] = getSharedKey(credentials.get(), verb, resource, date, headers);
		} else {
			headers["Authorization"] = "Bearer " + credentials.get().secret;
		}
	}
}

void AzureBlobStoreEndpoint::setRequestHeaders(const std::string& verb,
                                                const std::string& resource,
                                                HTTP::Headers& headers) {
	setAllRequestHeaders(verb, resource, headers);
}

static Future<bool> bucketExists_impl(Reference<AzureBlobStoreEndpoint> b, std::string bucket) {
	co_await b->requestRateRead->getAllowance(1);

	std::string resource = "/" + bucket + "?restype=container";
	HTTP::Headers headers;
	Reference<HTTP::IncomingResponse> r = co_await b->doRequest("HEAD", resource, headers, nullptr, 0, { 200, 404 });
	co_return r->code == 200;
}

Future<bool> AzureBlobStoreEndpoint::bucketExists(std::string const& bucket) {
	return bucketExists_impl(Reference<AzureBlobStoreEndpoint>::addRef(this), bucket);
}

static Future<bool> objectExists_impl(Reference<AzureBlobStoreEndpoint> b,
                                      std::string bucket,
                                      std::string object) {
	co_await b->requestRateRead->getAllowance(1);

	std::string resource = "/" + bucket + "/" + object;
	HTTP::Headers headers;
	addAzureEncryptionHeaders(headers, false /* isWriteRequest */);

	Reference<HTTP::IncomingResponse> r = co_await b->doRequest("HEAD", resource, headers, nullptr, 0, { 200, 404 });
	co_return r->code == 200;
}

Future<bool> AzureBlobStoreEndpoint::objectExists(std::string const& bucket, std::string const& object) {
	return objectExists_impl(Reference<AzureBlobStoreEndpoint>::addRef(this), bucket, object);
}

static Future<int64_t> objectSize_impl(Reference<AzureBlobStoreEndpoint> b,
                                       std::string bucket,
                                       std::string object) {
	co_await b->requestRateRead->getAllowance(1);

	std::string resource = "/" + bucket + "/" + object;
	HTTP::Headers headers;
	addAzureEncryptionHeaders(headers, false /* isWriteRequest */);

	Reference<HTTP::IncomingResponse> r = co_await b->doRequest("HEAD", resource, headers, nullptr, 0, { 200, 404 });
	if (r->code == 404)
		throw file_not_found();

	co_return r->data.contentLen;
}

Future<int64_t> AzureBlobStoreEndpoint::objectSize(std::string const& bucket, std::string const& object) {
	return objectSize_impl(Reference<AzureBlobStoreEndpoint>::addRef(this), bucket, object);
}

static Future<int> readObject_impl(Reference<AzureBlobStoreEndpoint> b,
                                   std::string bucket,
                                   std::string object,
                                   void* data,
                                   int length,
                                   int64_t offset) {
	if (length <= 0)
		co_return 0;

	co_await b->requestRateRead->getAllowance(1);

	std::string resource = "/" + bucket + "/" + object;
	HTTP::Headers headers;
	headers["Range"] = format("bytes=%lld-%lld", offset, offset + length - 1);
	addAzureEncryptionHeaders(headers, false /* isWriteRequest */);

	Reference<HTTP::IncomingResponse> r =
	    co_await b->doRequest("GET", resource, headers, nullptr, 0, { 200, 206, 404 });

	if (r->code == 404)
		throw file_not_found();

	if (r->data.contentLen != r->data.content.size())
		throw io_error();

	// Copy the output bytes, server could have sent more or less bytes than requested so copy at most length bytes
	memcpy(data, r->data.content.data(), std::min<int64_t>(r->data.contentLen, length));
	co_return r->data.contentLen;
}

Future<int> AzureBlobStoreEndpoint::readObject(std::string const& bucket,
                                               std::string const& object,
                                               void* data,
                                               int length,
                                               int64_t offset) {
	return readObject_impl(Reference<AzureBlobStoreEndpoint>::addRef(this), bucket, object, data, length, offset);
}

static Future<Void> deleteObject_impl(Reference<AzureBlobStoreEndpoint> b,
                                      std::string bucket,
                                      std::string object) {
	co_await b->requestRateDelete->getAllowance(1);

	std::string resource = "/" + bucket + "/" + object;
	HTTP::Headers headers;

	Reference<HTTP::IncomingResponse> r =
	    co_await b->doRequest("DELETE", resource, headers, nullptr, 0, { 202, 404 });

	if (r->code == 404) {
		TraceEvent(SevWarnAlways, "AzureBlobStoreDeleteObjectMissing")
		    .detail("Host", b->host)
		    .detail("Bucket", bucket)
		    .detail("Object", object);
	}

	co_return;
}

Future<Void> AzureBlobStoreEndpoint::deleteObject(std::string const& bucket, std::string const& object) {
	return deleteObject_impl(Reference<AzureBlobStoreEndpoint>::addRef(this), bucket, object);
}

static AsyncResult<std::string> readEntireFile_impl(Reference<AzureBlobStoreEndpoint> b,
                                                    std::string bucket,
                                                    std::string object) {
	co_await b->requestRateRead->getAllowance(1);

	std::string resource = "/" + bucket + "/" + object;
	HTTP::Headers headers;
	addAzureEncryptionHeaders(headers, false /* isWriteRequest */);

	Reference<HTTP::IncomingResponse> r = co_await b->doRequest("GET", resource, headers, nullptr, 0, { 200, 404 });
	if (r->code == 404)
		throw file_not_found();

	co_return r->data.content;
}

AsyncResult<std::string> AzureBlobStoreEndpoint::readEntireFile(std::string const& bucket,
                                                                std::string const& object) {
	return readEntireFile_impl(Reference<AzureBlobStoreEndpoint>::addRef(this), bucket, object);
}

static Future<Void> writeEntireFileFromBuffer_impl(Reference<AzureBlobStoreEndpoint> b,
                                                   std::string bucket,
                                                   std::string object,
                                                   UnsentPacketQueue* pContent,
                                                   int contentLen,
                                                   std::string contentMD5) {
	if (contentLen > b->knobs.multipart_max_part_size)
		throw file_too_large();

	co_await b->requestRateWrite->getAllowance(1);
	co_await b->concurrentUploads.take();
	FlowLock::Releaser uploadReleaser(b->concurrentUploads, 1);

	std::string resource = "/" + bucket + "/" + object;
	HTTP::Headers headers;
	headers["Content-Length"] = std::to_string(contentLen);
	headers["Content-MD5"] = contentMD5;
	headers["x-ms-blob-type"] = "BlockBlob";
	addAzureEncryptionHeaders(headers, true /* isWriteRequest */);

	Reference<HTTP::IncomingResponse> r =
	    co_await b->doRequest("PUT", resource, headers, pContent, contentLen, { 201 });

	co_return;
}

Future<Void> AzureBlobStoreEndpoint::writeEntireFileFromBuffer(std::string const& bucket,
                                                               std::string const& object,
                                                               UnsentPacketQueue* pContent,
                                                               int contentLen,
                                                               std::string const& contentMD5) {
	return writeEntireFileFromBuffer_impl(
	    Reference<AzureBlobStoreEndpoint>::addRef(this), bucket, object, pContent, contentLen, contentMD5);
}

static Future<std::string> beginMultiPartUpload_impl(Reference<AzureBlobStoreEndpoint> b,
                                                     std::string bucket,
                                                     std::string object) {
	// Azure uses Put Block / Put Block List instead of multipart uploads.
	// Return the object name as the "upload ID" for interface compatibility.
	co_return object;
}

Future<std::string> AzureBlobStoreEndpoint::beginMultiPartUpload(std::string const& bucket,
                                                                 std::string const& object) {
	return beginMultiPartUpload_impl(Reference<AzureBlobStoreEndpoint>::addRef(this), bucket, object);
}

// Azure block ID requirements (per Put Block API docs):
// - Block IDs must be base64-encoded and URL-encoded when passed in query string
// - All block IDs for a single blob must have the same encoded length (before URL encoding)
// - Block ID max size is 64 bytes (after base64 decode)
// We use 8-digit zero-padded part numbers, which produces consistent length base64 strings.
static std::string makeBlockID(unsigned int partNumber) {
	// Create a fixed-width string representation of the part number (8 digits, zero-padded)
	std::string partStr = format("%08u", partNumber);
	// Base64 encode it
	std::string encoded = base64::encoder::from_string(partStr);
	// Remove trailing newline from libb64
	if (!encoded.empty() && encoded.back() == '\n') {
		encoded.pop_back();
	}
	return encoded;
}

// Helper function to URL-encode a base64 block ID for use in query parameters
static std::string urlEncodeBlockID(const std::string& blockId) {
	std::string result;
	for (char c : blockId) {
		if (c == '+') {
			result += "%2B";
		} else if (c == '/') {
			result += "%2F";
		} else if (c == '=') {
			result += "%3D";
		} else {
			result += c;
		}
	}
	return result;
}

static Future<std::string> uploadPart_impl(Reference<AzureBlobStoreEndpoint> b,
                                           std::string bucket,
                                           std::string object,
                                           std::string uploadID,
                                           unsigned int partNumber,
                                           UnsentPacketQueue* pContent,
                                           int contentLen,
                                           std::string contentMD5) {
	co_await b->requestRateWrite->getAllowance(1);
	co_await b->concurrentUploads.take();
	FlowLock::Releaser uploadReleaser(b->concurrentUploads, 1);

	std::string blockId = makeBlockID(partNumber);
	std::string urlEncodedBlockId = urlEncodeBlockID(blockId);
	std::string resource = "/" + bucket + "/" + object + "?comp=block&blockid=" + urlEncodedBlockId;

	HTTP::Headers headers;
	headers["Content-Length"] = std::to_string(contentLen);
	if (!contentMD5.empty()) {
		headers["Content-MD5"] = contentMD5;
	}
	addAzureEncryptionHeaders(headers, true /* isWriteRequest */);

	Reference<HTTP::IncomingResponse> r =
	    co_await b->doRequest("PUT", resource, headers, pContent, contentLen, { 201 });

	// Return the block ID - this will be used in finishMultiPartUpload to build the block list
	co_return blockId;
}

Future<std::string> AzureBlobStoreEndpoint::uploadPart(std::string const& bucket,
                                                       std::string const& object,
                                                       std::string const& uploadID,
                                                       unsigned int partNumber,
                                                       UnsentPacketQueue* pContent,
                                                       int contentLen,
                                                       std::string const& contentMD5) {
	return uploadPart_impl(Reference<AzureBlobStoreEndpoint>::addRef(this),
	                       bucket,
	                       object,
	                       uploadID,
	                       partNumber,
	                       pContent,
	                       contentLen,
	                       contentMD5);
}

static Future<Optional<std::string>> finishMultiPartUpload_impl(Reference<AzureBlobStoreEndpoint> b,
                                                                std::string bucket,
                                                                std::string object,
                                                                std::string uploadID,
                                                                IBlobStoreEndpoint::MultiPartSetT parts,
                                                                int64_t totalSize) {
	UnsentPacketQueue blockListContent;
	co_await b->requestRateWrite->getAllowance(1);

	// Request body is XML with the list of block IDs to commit
	// The parts map contains partNumber -> PartInfo (where etag holds the blockId returned from uploadPart)
	std::string blockListXml = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n<BlockList>\n";
	for (const auto& p : parts) {
		// Use <Latest> to commit the most recently uploaded version of each block
		blockListXml += "  <Latest>" + p.second.etag + "</Latest>\n";
	}
	blockListXml += "</BlockList>";

	std::string resource = "/" + bucket + "/" + object + "?comp=blocklist";
	HTTP::Headers headers;
	headers["Content-Length"] = std::to_string(blockListXml.size());
	headers["x-ms-blob-content-type"] = "application/octet-stream";
	addAzureEncryptionHeaders(headers, true /* isWriteRequest */);

	PacketWriter pw(blockListContent.getWriteBuffer(blockListXml.size()), nullptr, Unversioned());
	pw.serializeBytes(blockListXml);

	Reference<HTTP::IncomingResponse> r =
	    co_await b->doRequest("PUT", resource, headers, &blockListContent, blockListXml.size(), { 201 });

	co_return Optional<std::string>();
}

Future<Optional<std::string>> AzureBlobStoreEndpoint::finishMultiPartUpload(std::string const& bucket,
                                                                            std::string const& object,
                                                                            std::string const& uploadID,
                                                                            MultiPartSetT const& parts,
                                                                            int64_t totalSize) {
	return finishMultiPartUpload_impl(
	    Reference<AzureBlobStoreEndpoint>::addRef(this), bucket, object, uploadID, parts, totalSize);
}

static Future<Void> listObjectsStream_impl(Reference<AzureBlobStoreEndpoint> b,
                                           std::string bucket,
                                           PromiseStream<IBlobStoreEndpoint::ListResult> results,
                                           Optional<std::string> prefix,
                                           Optional<char> delimiter,
                                           int maxDepth,
                                           std::function<bool(std::string const&)> recurseFilter) {
	std::string resource = "/" + bucket;
	std::string qs = "restype=container&comp=list&maxresults=1000";

	if (prefix.present() && !prefix.get().empty()) {
		qs.append("&prefix=").append(prefix.get());
	}
	if (delimiter.present()) {
		qs.append("&delimiter=").append(std::string(1, delimiter.get()));
	}

	std::string marker;
	bool more = true;
	std::vector<Future<Void>> subLists;

	while (more) {
		co_await b->requestRateList->getAllowance(1);
		co_await b->concurrentLists.take();
		FlowLock::Releaser listReleaser(b->concurrentLists, 1);

		HTTP::Headers headers;
		std::string fullResource = resource + "?" + qs;
		if (!marker.empty()) {
			fullResource.append("&marker=").append(marker);
		}

		Reference<HTTP::IncomingResponse> r =
		    co_await b->doRequest("GET", fullResource, headers, nullptr, 0, { 200 });
		listReleaser.release();

		IBlobStoreEndpoint::ListResult listResult;
		rapidxml::xml_document<> doc;

		// Copy content because rapidxml will modify it during parse
		std::string content = r->data.content;
		doc.parse<0>((char*)content.c_str());

		// Azure response: <EnumerationResults>
		rapidxml::xml_node<>* result = doc.first_node("EnumerationResults");
		if (result == nullptr) {
			throw http_bad_response();
		}

		rapidxml::xml_node<>* blobs = result->first_node("Blobs");
		if (blobs == nullptr) {
			throw http_bad_response();
		}

		// Parse blobs
		rapidxml::xml_node<>* blob = blobs->first_node("Blob");
		while (blob != nullptr) {
			IBlobStoreEndpoint::ObjectInfo objectInfo;

			rapidxml::xml_node<>* nameNode = blob->first_node("Name");
			if (nameNode == nullptr) {
				throw http_bad_response();
			}
			objectInfo.name = nameNode->value();

			rapidxml::xml_node<>* props = blob->first_node("Properties");
			if (props != nullptr) {
				rapidxml::xml_node<>* sizeNode = props->first_node("Content-Length");
				if (sizeNode != nullptr) {
					objectInfo.size = strtoull(sizeNode->value(), nullptr, 10);
				}
			}

			listResult.objects.push_back(objectInfo);
			blob = blob->next_sibling("Blob");
		}

		// Parse BlobPrefix (common prefixes)
		rapidxml::xml_node<>* blobPrefix = blobs->first_node("BlobPrefix");
		while (blobPrefix != nullptr) {
			rapidxml::xml_node<>* prefixName = blobPrefix->first_node("Name");
			if (prefixName != nullptr) {
				const char* prefixValue = prefixName->value();

				// If recursing, queue a sub-request, otherwise add to common prefixes
				if (maxDepth > 0) {
					if (!recurseFilter || recurseFilter(prefixValue)) {
						subLists.push_back(
						    b->listObjectsStream(bucket, results, prefixValue, delimiter, maxDepth - 1, recurseFilter));
					}
				} else {
					listResult.commonPrefixes.push_back(prefixValue);
				}
			}
			blobPrefix = blobPrefix->next_sibling("BlobPrefix");
		}

		// Check for NextMarker
		rapidxml::xml_node<>* nextMarker = result->first_node("NextMarker");
		if (nextMarker != nullptr && nextMarker->value() != nullptr && strlen(nextMarker->value()) > 0) {
			marker = nextMarker->value();
			more = true;
		} else {
			more = false;
		}

		results.send(listResult);
	}

	// Wait for any sub-listings to finish
	co_await waitForAll(subLists);

	co_return;
}

Future<Void> AzureBlobStoreEndpoint::listObjectsStream(std::string const& bucket,
                                                       PromiseStream<ListResult> results,
                                                       Optional<std::string> prefix,
                                                       Optional<char> delimiter,
                                                       int maxDepth,
                                                       std::function<bool(std::string const&)> recurseFilter) {
	return listObjectsStream_impl(
	    Reference<AzureBlobStoreEndpoint>::addRef(this), bucket, results, prefix, delimiter, maxDepth, recurseFilter);
}

static AsyncResult<std::vector<std::string>> listBuckets_impl(Reference<AzureBlobStoreEndpoint> b) {
	co_await b->requestRateRead->getAllowance(1);

	std::string resource = "/?comp=list";
	HTTP::Headers headers;

	Reference<HTTP::IncomingResponse> r = co_await b->doRequest("GET", resource, headers, nullptr, 0, { 200 });

	std::vector<std::string> buckets;

	rapidxml::xml_document<> doc;
	std::string content = r->data.content;
	doc.parse<0>(content.data());

	rapidxml::xml_node<>* root = doc.first_node("EnumerationResults");
	if (root) {
		rapidxml::xml_node<>* containersNode = root->first_node("Containers");
		if (containersNode) {
			for (rapidxml::xml_node<>* container = containersNode->first_node("Container"); container;
			     container = container->next_sibling("Container")) {
				rapidxml::xml_node<>* nameNode = container->first_node("Name");
				if (nameNode && nameNode->value()) {
					buckets.push_back(nameNode->value());
				}
			}
		}
	}

	co_return buckets;
}

AsyncResult<std::vector<std::string>> AzureBlobStoreEndpoint::listBuckets() {
	return listBuckets_impl(Reference<AzureBlobStoreEndpoint>::addRef(this));
}

static Future<Void> createBucket_impl(Reference<AzureBlobStoreEndpoint> b, std::string bucket) {
	co_await b->requestRateWrite->getAllowance(1);

	// The identity may only have data-plane access, not permission to create containers.
	bool exists = co_await b->bucketExists(bucket);
	if (!exists) {
		std::string resource = "/" + bucket + "?restype=container";
		HTTP::Headers headers;

		Reference<HTTP::IncomingResponse> r =
		    co_await b->doRequest("PUT", resource, headers, nullptr, 0, { 201, 409 });

		// 409 = container already exists, which is fine
		if (r->code == 409) {
			TraceEvent(SevInfo, "AzureBlobStoreCreateBucketAlreadyExists")
			    .detail("Host", b->host)
			    .detail("Bucket", bucket);
		}
	}

	co_return;
}

Future<Void> AzureBlobStoreEndpoint::createBucket(std::string const& bucket) {
	return createBucket_impl(Reference<AzureBlobStoreEndpoint>::addRef(this), bucket);
}
