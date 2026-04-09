/*
 * GCSBlobStore.cpp
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

#include "fdbclient/GCSBlobStore.h"
#include "fdbrpc/HTTP.h"
#include "fdbclient/json_spirit/json_spirit_reader_template.h"
#include "fdbclient/JSONDoc.h"
#include "flow/CoroUtils.h"
#include "flow/Trace.h"
#include "libb64/encode.h"
#include <openssl/md5.h>
#include <unordered_set>

// GCS requires all parts except the last to be at least 256KB due to their internal buffering
constexpr int64_t GCS_MIN_PART_SIZE = 256 * 1024;

static const std::unordered_set<char> GCS_RESERVED_CHARS = { '!', '#', '$', '&', '\'', '(', ')', '*', '+',
	                                                         ',', '/', ':', ';',  '=',  '?', '@', '[', ']',
	                                                         ' ' };

static std::string gcpPathParamUrlEncode(const std::string& s) {
	std::string o;
	o.reserve(s.size() * 3);
	char buf[4];
	for (auto c : s) {
		if (GCS_RESERVED_CHARS.count(c)) {
			sprintf(buf, "%%%.02X", c);
			o.append(buf);
		} else {
			o.append(&c, 1);
		}
	}
	return o;
}

Optional<GCSBlobStoreEndpoint::Credentials> parseGcpCredentials(Optional<StringRef> const& credString) {
	if (credString.present()) {
		return GCSBlobStoreEndpoint::Credentials{ credString.get().toString() };
	}

	return Optional<GCSBlobStoreEndpoint::Credentials>();
}

GCSBlobStoreEndpoint::GCSBlobStoreEndpoint(std::string const& host,
                                           std::string const& service,
                                           Optional<std::string> const& proxyHost,
                                           Optional<std::string> const& proxyPort,
                                           Optional<StringRef> const& creds,
                                           std::string const& projectId,
                                           BlobKnobs const& knobs,
                                           HTTP::Headers extraHeaders)
  : IBlobStoreEndpoint(host, service, "auto", proxyHost, proxyPort, knobs, extraHeaders),
    credentials(parseGcpCredentials(creds)), projectId(projectId) {
	if (!credentials.present()) {
		throw backup_auth_missing();
	}
}

std::string GCSBlobStoreEndpoint::getResourceURL(std::string resource, std::string params) const {
	if (!params.empty())
		params.append("&");
	params.append("p=gcs");
	if (!projectId.empty()) {
		params.append("&gcspid=").append(projectId);
	}
	return IBlobStoreEndpoint::getResourceURL(resource, params);
}

bool GCSBlobStoreEndpoint::extractCredentialFields(JSONDoc& account) {
	if (!credentials.present())
		return false;
	Credentials creds = credentials.get();
	std::string token;
	if (account.tryGet("token", token)) {
		creds.token = token;
		credentials = creds;
		TraceEvent("GCSBlobStoreEndpointUpdatedSecret").detail("CredentialsKey", credentialFileKey());
		return true;
	}
	return false;
}

void GCSBlobStoreEndpoint::setRequestHeaders(const std::string& verb,
                                              const std::string& resource,
                                              HTTP::Headers& headers) {
	headers["Accept"] = "application/json";
	if (credentials.present()) {
		headers["Authorization"] = "Bearer " + credentials.get().token;
	}
}

std::string constructResourceURL(std::string const& bucket,
                                 std::string const& object,
                                 std::string const& queryStrings) {
	return format("/storage/v1/b/%s/o/%s?%s",
	              gcpPathParamUrlEncode(bucket).c_str(),
	              gcpPathParamUrlEncode(object).c_str(),
	              queryStrings.c_str());
}

Future<int> readObject_impl(Reference<GCSBlobStoreEndpoint> bstore,
                            std::string bucket,
                            std::string object,
                            void* data,
                            int length,
                            int64_t offset) {
	if (length <= 0)
		co_return 0;
	co_await bstore->requestRateRead->getAllowance(1);

	std::string resource = constructResourceURL(bucket, object, "alt=media");
	HTTP::Headers headers;
	if (offset > 0 || length > 0) {
		headers["Range"] = format("bytes=%lld-%lld", offset, offset + length - 1);
	}
	Reference<HTTP::IncomingResponse> r =
	    co_await bstore->doRequest("GET", resource, headers, nullptr, 0, { 200, 206, 404 });

	if (r->code == 404)
		throw file_not_found();
	if (r->data.contentLen != r->data.content.size())
		throw io_error();

	memcpy(data, r->data.content.data(), std::min<int64_t>(r->data.contentLen, length));
	co_return r->data.contentLen;
}

Future<int> GCSBlobStoreEndpoint::readObject(std::string const& bucket,
                                             std::string const& object,
                                             void* data,
                                             int length,
                                             int64_t offset) {
	return readObject_impl(Reference<GCSBlobStoreEndpoint>::addRef(this), bucket, object, data, length, offset);
}

AsyncResult<std::string> readEntireFile_impl(Reference<GCSBlobStoreEndpoint> bstore,
                                             std::string bucket,
                                             std::string object) {
	co_await bstore->requestRateRead->getAllowance(1);
	std::string resource = constructResourceURL(bucket, object, "alt=media");
	HTTP::Headers headers;
	Reference<HTTP::IncomingResponse> r =
	    co_await bstore->doRequest("GET", resource, headers, nullptr, 0, { 200, 206, 404 });
	if (r->code == 404)
		throw file_not_found();
	co_return r->data.content;
}

AsyncResult<std::string> GCSBlobStoreEndpoint::readEntireFile(std::string const& bucket, std::string const& object) {
	return readEntireFile_impl(Reference<GCSBlobStoreEndpoint>::addRef(this), bucket, object);
}

Future<bool> bucketExists_impl(Reference<GCSBlobStoreEndpoint> bstore, std::string bucket) {
	co_await bstore->requestRateRead->getAllowance(1);
	std::string resource = format("/storage/v1/b/%s", gcpPathParamUrlEncode(bucket).c_str());
	Reference<HTTP::IncomingResponse> r = co_await bstore->doRequest("GET", resource, {}, nullptr, 0, { 200, 404 });
	co_return r->code == 200;
}

Future<bool> GCSBlobStoreEndpoint::bucketExists(std::string const& bucket) {
	return bucketExists_impl(Reference<GCSBlobStoreEndpoint>::addRef(this), bucket);
}

Future<Void> createBucket_impl(Reference<GCSBlobStoreEndpoint> bstore, std::string bucket) {
	bool exists = co_await bstore->bucketExists(bucket);
	if (exists) {
		TraceEvent(SevInfo, "GCSBucketAlreadyExists").detail("Bucket", bucket);
		co_return;
	}

	if (bstore->projectId.empty()) {
		TraceEvent(SevError, "GCSBucketCreateMissingProject")
		    .detail("Bucket", bucket)
		    .detail("Hint", "Set gcs_project_id (or gcspid) URL parameter");
		throw backup_invalid_url();
	}

	co_await bstore->requestRateWrite->getAllowance(1);

	std::string resource = "/storage/v1/b?project=" + bstore->projectId;
	std::string body = "{\"name\":\"" + bucket + "\"}";

	UnsentPacketQueue packets;
	PacketWriter pw(packets.getWriteBuffer(body.size()), nullptr, Unversioned());
	pw.serializeBytes(body);

	HTTP::Headers headers;
	headers["Content-Type"] = "application/json";
	headers["Content-Length"] = std::to_string(body.size());

	Reference<HTTP::IncomingResponse> r =
	    co_await bstore->doRequest("POST", resource, headers, &packets, body.size(), { 200, 409 });

	if (r->code == 409) {
		TraceEvent(SevInfo, "GCSBucketAlreadyExists").detail("Bucket", bucket);
	}
}

Future<Void> GCSBlobStoreEndpoint::createBucket(std::string const& bucket) {
	return createBucket_impl(Reference<GCSBlobStoreEndpoint>::addRef(this), bucket);
}

AsyncResult<std::vector<std::string>> listBuckets_impl(Reference<GCSBlobStoreEndpoint> bstore) {
	co_await bstore->requestRateRead->getAllowance(1);
	Reference<HTTP::IncomingResponse> r = co_await bstore->doRequest("GET", "/storage/v1/b", {}, nullptr, 0, { 200 });

	std::string response(r->data.content.begin(), r->data.content.end());

	json_spirit::mValue json;
	json_spirit::read_string(response, json);

	if (json.type() != json_spirit::obj_type)
		throw http_bad_response();

	json_spirit::mObject obj = json.get_obj();
	std::vector<std::string> buckets;

	auto items = obj.find("items");
	if (items != obj.end() && items->second.type() == json_spirit::array_type) {
		json_spirit::mArray itemsArray = items->second.get_array();
		for (const auto& item : itemsArray) {
			if (item.type() != json_spirit::obj_type)
				continue;

			json_spirit::mObject itemObj = item.get_obj();
			auto nameIterable = itemObj.find("name");
			if (nameIterable != itemObj.end() && nameIterable->second.type() == json_spirit::str_type) {
				buckets.push_back(nameIterable->second.get_str());
			}
		}
	}

	co_return buckets;
}

AsyncResult<std::vector<std::string>> GCSBlobStoreEndpoint::listBuckets() {
	return listBuckets_impl(Reference<GCSBlobStoreEndpoint>::addRef(this));
}

Future<bool> objectExists_impl(Reference<GCSBlobStoreEndpoint> bstore, std::string bucket, std::string object) {
	co_await bstore->requestRateRead->getAllowance(1);
	std::string resource = format("/storage/v1/b/%s/o/%s",
	                              gcpPathParamUrlEncode(bucket).c_str(),
	                              gcpPathParamUrlEncode(object).c_str());
	Reference<HTTP::IncomingResponse> r = co_await bstore->doRequest("GET", resource, {}, nullptr, 0, { 200, 404 });
	co_return r->code == 200;
}

Future<bool> GCSBlobStoreEndpoint::objectExists(std::string const& bucket, std::string const& object) {
	return objectExists_impl(Reference<GCSBlobStoreEndpoint>::addRef(this), bucket, object);
}

Future<int64_t> objectSize_impl(Reference<GCSBlobStoreEndpoint> bstore, std::string bucket, std::string object) {
	co_await bstore->requestRateRead->getAllowance(1);

	std::string resource = constructResourceURL(bucket, object, "fields=size");
	Reference<HTTP::IncomingResponse> r = co_await bstore->doRequest("GET", resource, {}, nullptr, 0, { 200, 404 });
	if (r->code == 404)
		throw file_not_found();
	std::string response(r->data.content.begin(), r->data.content.end());

	json_spirit::mValue json;
	json_spirit::read_string(response, json);

	if (json.type() != json_spirit::obj_type)
		throw http_bad_response();

	json_spirit::mObject obj = json.get_obj();
	auto sizeIt = obj.find("size");
	if (sizeIt != obj.end() && sizeIt->second.type() == json_spirit::str_type)
		co_return std::stoll(sizeIt->second.get_str());

	throw http_bad_response();
}

Future<int64_t> GCSBlobStoreEndpoint::objectSize(std::string const& bucket, std::string const& object) {
	return objectSize_impl(Reference<GCSBlobStoreEndpoint>::addRef(this), bucket, object);
}

Future<Void> deleteObject_impl(Reference<GCSBlobStoreEndpoint> bstore, std::string bucket, std::string object) {
	co_await bstore->requestRateDelete->getAllowance(1);

	std::string resource = format("/storage/v1/b/%s/o/%s",
	                              gcpPathParamUrlEncode(bucket).c_str(),
	                              gcpPathParamUrlEncode(object).c_str());
	Reference<HTTP::IncomingResponse> r =
	    co_await bstore->doRequest("DELETE", resource, {}, nullptr, 0, { 200, 204, 404 });
	if (r->code == 404) {
		TraceEvent(SevWarnAlways, "GCSBlobStoreDeleteObjectMissing")
		    .detail("Host", bstore->host)
		    .detail("Bucket", bucket)
		    .detail("Object", object);
	}

	co_return;
}

Future<Void> GCSBlobStoreEndpoint::deleteObject(std::string const& bucket, std::string const& object) {
	return deleteObject_impl(Reference<GCSBlobStoreEndpoint>::addRef(this), bucket, object);
}

void checkMd5Hash(Reference<HTTP::IncomingResponse> response, std::string const& contentMD5) {
	json_spirit::mValue respJson;
	if (!json_spirit::read_string(response->data.content, respJson))
		throw http_request_failed();

	auto obj = respJson.get_obj();
	auto it = obj.find("md5Hash");
	if (it == obj.end() || it->second.get_str() != contentMD5)
		throw checksum_failed();
}

Future<Void> writeEntireFileFromBuffer_impl(Reference<GCSBlobStoreEndpoint> bstore,
                                            std::string bucket,
                                            std::string object,
                                            UnsentPacketQueue* pContent,
                                            int contentLen,
                                            std::string contentMD5) {
	if (contentLen > bstore->knobs.multipart_max_part_size)
		throw file_too_large();

	co_await bstore->requestRateWrite->getAllowance(1);
	co_await bstore->concurrentUploads.take();
	FlowLock::Releaser uploadReleaser(bstore->concurrentUploads, 1);

	std::string resource = format("/upload/storage/v1/b/%s/o?uploadType=media&name=%s",
	                              gcpPathParamUrlEncode(bucket).c_str(),
	                              gcpPathParamUrlEncode(object).c_str());

	HTTP::Headers headers;
	headers["Content-Type"] = "application/octet-stream";
	headers["Content-Length"] = std::to_string(contentLen);

	Reference<HTTP::IncomingResponse> r =
	    co_await bstore->doRequest("POST", resource, headers, pContent, contentLen, { 200, 201 });

	if (r->code != 200 && r->code != 201)
		throw http_request_failed();

	checkMd5Hash(r, contentMD5);
	co_return;
}

Future<Void> GCSBlobStoreEndpoint::writeEntireFileFromBuffer(std::string const& bucket,
                                                             std::string const& object,
                                                             UnsentPacketQueue* pContent,
                                                             int contentLen,
                                                             std::string const& contentMD5) {
	return writeEntireFileFromBuffer_impl(
	    Reference<GCSBlobStoreEndpoint>::addRef(this), bucket, object, pContent, contentLen, contentMD5);
}

Future<std::string> beginMultiPartUpload_impl(Reference<GCSBlobStoreEndpoint> bstore,
                                              std::string bucket,
                                              std::string object) {
	co_await bstore->requestRateWrite->getAllowance(1);

	std::string resource = format("/upload/storage/v1/b/%s/o?uploadType=resumable&name=%s",
	                              gcpPathParamUrlEncode(bucket).c_str(),
	                              gcpPathParamUrlEncode(object).c_str());

	HTTP::Headers headers;
	headers["Content-Type"] = "application/octet-stream";
	headers["Content-Length"] = "0";

	Reference<HTTP::IncomingResponse> r = co_await bstore->doRequest("POST", resource, headers, nullptr, 0, { 200 });

	auto it = r->data.headers.find("Location");
	if (it == r->data.headers.end())
		throw http_bad_response();

	std::string uploadURL = it->second;
	size_t uploadIdPos = uploadURL.find("upload_id=");
	if (uploadIdPos == std::string::npos)
		throw http_bad_response();

	co_return uploadURL.substr(uploadIdPos + 10);
}

Future<std::string> GCSBlobStoreEndpoint::beginMultiPartUpload(std::string const& bucket, std::string const& object) {
	return beginMultiPartUpload_impl(Reference<GCSBlobStoreEndpoint>::addRef(this), bucket, object);
}

std::string constructResumableUploadURL(std::string const& bucket, std::string const& uploadID) {
	return format("/upload/storage/v1/b/%s/o?uploadType=resumable&upload_id=%s",
	              gcpPathParamUrlEncode(bucket).c_str(),
	              gcpPathParamUrlEncode(uploadID).c_str());
}

Future<Void> checkUploadPartProgress(Reference<GCSBlobStoreEndpoint> bstore,
                                     std::string resource,
                                     int64_t expectedBytes,
                                     unsigned int partNumber,
                                     std::string uploadID) {
	int retryCount = 0;
	int maxRetries = bstore->knobs.gcs_upload_progress_timeout / bstore->knobs.gcs_upload_progress_check_interval;
	HTTP::Headers headers;
	headers["Content-Length"] = "0";
	headers["Content-Range"] = "bytes */*";

	while (true) {
		Reference<HTTP::IncomingResponse> r = co_await bstore->doRequest("PUT", resource, headers, nullptr, 0, { 308 });

		int64_t bytesReceived = 0;
		if (r->code == 308) {
			auto rangeIt = r->data.headers.find("Range");
			if (rangeIt != r->data.headers.end()) {
				std::string rangeValue = rangeIt->second;
				size_t dashPos = rangeValue.find('-');
				if (dashPos != std::string::npos) {
					std::string endStr = rangeValue.substr(dashPos + 1);
					bytesReceived = std::stoll(endStr) + 1;
				}
			}
		}

		if (bytesReceived >= expectedBytes) {
			co_return;
		}

		if (retryCount >= maxRetries) {
			TraceEvent(SevWarn, "GCSUploadPartProgressTimeout")
			    .detail("UploadID", uploadID)
			    .detail("PartNumber", partNumber)
			    .detail("ExpectedBytes", expectedBytes)
			    .detail("RetryCount", retryCount)
			    .detail("BytesReceived", bytesReceived)
			    .detail("TimeoutSeconds", bstore->knobs.gcs_upload_progress_timeout)
			    .detail("CheckIntervalSeconds", bstore->knobs.gcs_upload_progress_check_interval);
			throw http_request_failed();
		}

		retryCount++;
		co_await delay(bstore->knobs.gcs_upload_progress_check_interval);
	}
}

// GCS resumable uploads are inherently sequential — each part must wait for GCS to acknowledge
// all prior bytes before sending. The concurrent_writes_per_file knob has no effect for GCS multipart.
Future<std::string> uploadPart_impl(Reference<GCSBlobStoreEndpoint> bstore,
                                    std::string bucket,
                                    std::string object,
                                    std::string uploadID,
                                    unsigned int partNumber,
                                    UnsentPacketQueue* pContent,
                                    int contentLen,
                                    std::string contentMD5) {
	co_await bstore->requestRateWrite->getAllowance(1);
	co_await bstore->concurrentUploads.take();
	FlowLock::Releaser uploadReleaser(bstore->concurrentUploads, 1);

	std::string resource = constructResumableUploadURL(bucket, uploadID);
	int64_t rangeStart = (partNumber - 1) * bstore->knobs.multipart_min_part_size;

	if (partNumber > 1) {
		co_await checkUploadPartProgress(bstore, resource, rangeStart, partNumber, uploadID);
	}

	int64_t rangeEnd = rangeStart + contentLen - 1;
	HTTP::Headers headers;
	headers["Content-Type"] = "application/octet-stream";
	headers["Content-Length"] = std::to_string(contentLen);

	std::set<unsigned int> expectedCodes;
	if (contentLen < GCS_MIN_PART_SIZE) {
		int64_t totalSize = rangeStart + contentLen;
		headers["Content-Range"] = format("bytes %lld-%lld/%lld", rangeStart, rangeEnd, totalSize);
		expectedCodes.insert(200);
		expectedCodes.insert(201);
	} else {
		headers["Content-Range"] = format("bytes %lld-%lld/*", rangeStart, rangeEnd);
		headers["x-goog-hash"] = "md5=" + contentMD5;
		expectedCodes.insert(308);
	}

	Reference<HTTP::IncomingResponse> r =
	    co_await bstore->doRequest("PUT", resource, headers, pContent, contentLen, expectedCodes);

	co_return format("part-%d", partNumber);
}

Future<std::string> GCSBlobStoreEndpoint::uploadPart(std::string const& bucket,
                                                     std::string const& object,
                                                     std::string const& uploadID,
                                                     unsigned int partNumber,
                                                     UnsentPacketQueue* pContent,
                                                     int contentLen,
                                                     std::string const& contentMD5) {
	return uploadPart_impl(Reference<GCSBlobStoreEndpoint>::addRef(this),
	                       bucket,
	                       object,
	                       uploadID,
	                       partNumber,
	                       pContent,
	                       contentLen,
	                       contentMD5);
}

Future<Optional<std::string>> finishMultiPartUpload_impl(Reference<GCSBlobStoreEndpoint> bstore,
                                                         std::string bucket,
                                                         std::string object,
                                                         std::string uploadID,
                                                         GCSBlobStoreEndpoint::MultiPartSetT parts,
                                                         int64_t totalSize) {
	co_await bstore->requestRateWrite->getAllowance(1);

	if (parts.empty())
		throw io_error();

	std::string resource = constructResumableUploadURL(bucket, uploadID);

	HTTP::Headers headers;
	headers["Content-Length"] = "0";
	headers["Content-Range"] = format("bytes */%lld", totalSize);

	Reference<HTTP::IncomingResponse> r = co_await bstore->doRequest("PUT", resource, headers, nullptr, 0, { 200, 201 });

	co_return Optional<std::string>();
}

Future<Optional<std::string>> GCSBlobStoreEndpoint::finishMultiPartUpload(std::string const& bucket,
                                                                          std::string const& object,
                                                                          std::string const& uploadID,
                                                                          MultiPartSetT const& parts,
                                                                          int64_t totalSize) {
	return finishMultiPartUpload_impl(
	    Reference<GCSBlobStoreEndpoint>::addRef(this), bucket, object, uploadID, parts, totalSize);
}

Future<Void> listObjectsStream_impl(Reference<GCSBlobStoreEndpoint> bstore,
                                    std::string bucket,
                                    PromiseStream<GCSBlobStoreEndpoint::ListResult> results,
                                    Optional<std::string> prefix,
                                    Optional<char> delimiter,
                                    int maxDepth,
                                    std::function<bool(std::string const&)> recurseFilter) {
	std::string resource =
	    format("/storage/v1/b/%s/o?maxResults=1000", gcpPathParamUrlEncode(bucket).c_str());
	if (prefix.present())
		resource += format("&prefix=%s", prefix.get().c_str());
	if (delimiter.present())
		resource += format("&delimiter=%c", delimiter.get());

	std::string pageToken;
	bool more = true;
	std::vector<Future<Void>> subLists;

	while (more) {
		co_await bstore->concurrentLists.take();
		FlowLock::Releaser listReleaser(bstore->concurrentLists, 1);

		std::string fullResource = resource;
		if (!pageToken.empty())
			fullResource += format("&pageToken=%s", pageToken.c_str());

		Reference<HTTP::IncomingResponse> r = co_await bstore->doRequest("GET", fullResource, {}, nullptr, 0, { 200 });
		listReleaser.release();

		std::string response(r->data.content.begin(), r->data.content.end());

		json_spirit::mValue json;
		json_spirit::read_string(response, json);

		if (json.type() != json_spirit::obj_type)
			throw http_bad_response();

		json_spirit::mObject obj = json.get_obj();
		GCSBlobStoreEndpoint::ListResult listResult;

		auto itemsIt = obj.find("items");
		if (itemsIt != obj.end() && itemsIt->second.type() == json_spirit::array_type) {
			json_spirit::mArray items = itemsIt->second.get_array();
			for (const auto& item : items) {
				if (item.type() != json_spirit::obj_type)
					throw http_bad_response();

				json_spirit::mObject itemObj = item.get_obj();
				GCSBlobStoreEndpoint::ObjectInfo objInfo;

				auto nameIterable = itemObj.find("name");
				if (nameIterable != itemObj.end() && nameIterable->second.type() == json_spirit::str_type)
					objInfo.name = nameIterable->second.get_str();
				else
					throw http_bad_response();

				auto sizeIterable = itemObj.find("size");
				if (sizeIterable != itemObj.end() && sizeIterable->second.type() == json_spirit::str_type)
					objInfo.size = std::stoll(sizeIterable->second.get_str());
				else
					throw http_bad_response();

				listResult.objects.push_back(objInfo);
			}
		}

		auto prefixesIterable = obj.find("prefixes");
		if (prefixesIterable != obj.end() && prefixesIterable->second.type() == json_spirit::array_type) {
			json_spirit::mArray prefixes = prefixesIterable->second.get_array();
			for (const auto& prefixVal : prefixes) {
				if (prefixVal.type() != json_spirit::str_type)
					throw http_bad_response();

				std::string commonPrefix = prefixVal.get_str();

				if (maxDepth > 0) {
					if (!recurseFilter || recurseFilter(commonPrefix)) {
						subLists.push_back(bstore->listObjectsStream(
						    bucket, results, commonPrefix, delimiter, maxDepth - 1, recurseFilter));
					}
				} else {
					listResult.commonPrefixes.push_back(commonPrefix);
				}
			}
		}

		results.send(listResult);

		auto nextPageIterable = obj.find("nextPageToken");
		if (nextPageIterable != obj.end() && nextPageIterable->second.type() == json_spirit::str_type) {
			pageToken = nextPageIterable->second.get_str();
			more = true;
		} else {
			more = false;
		}
	}

	co_await waitForAll(subLists);
	co_return;
}

Future<Void> GCSBlobStoreEndpoint::listObjectsStream(std::string const& bucket,
                                                     PromiseStream<ListResult> results,
                                                     Optional<std::string> prefix,
                                                     Optional<char> delimiter,
                                                     int maxDepth,
                                                     std::function<bool(std::string const&)> recurseFilter) {
	return listObjectsStream_impl(
	    Reference<GCSBlobStoreEndpoint>::addRef(this), bucket, results, prefix, delimiter, maxDepth, recurseFilter);
}
