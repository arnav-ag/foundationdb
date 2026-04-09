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
#include "fdbclient/JSONDoc.h"
#include "flow/Trace.h"

GCSBlobStoreEndpoint::GCSBlobStoreEndpoint(std::string const& host,
                                           std::string const& service,
                                           Optional<std::string> const& proxyHost,
                                           Optional<std::string> const& proxyPort,
                                           Optional<StringRef> const& creds,
                                           std::string const& projectId,
                                           BlobKnobs const& knobs,
                                           HTTP::Headers extraHeaders)
  : S3BlobStoreEndpoint(host,
                        service,
                        "auto", // GCS doesn't use AWS regions; "auto" works with SigV4 URI encoding
                        proxyHost,
                        proxyPort,
                        Optional<StringRef>(), // Don't pass creds to S3 — we handle auth ourselves
                        knobs,
                        extraHeaders),
    projectId(projectId) {
	if (creds.present()) {
		token = creds.get().toString();
	}
}

void GCSBlobStoreEndpoint::setRequestHeaders(std::string const& verb,
                                             std::string const& resource,
                                             HTTP::Headers& headers) {
	headers["Accept"] = "application/xml";
	if (!token.empty()) {
		headers["Authorization"] = "Bearer " + token;
	}
	if (!projectId.empty()) {
		headers["x-goog-project-id"] = projectId;
	}
}

Future<Void> GCSBlobStoreEndpoint::updateSecret() {
	return IBlobStoreEndpoint::updateSecret();
}

bool GCSBlobStoreEndpoint::extractCredentialFields(JSONDoc& account) {
	std::string newToken;
	if (account.tryGet("token", newToken)) {
		token = newToken;
		TraceEvent("GCSBlobStoreUpdatedSecret").detail("CredentialsKey", credentialFileKey());
		return true;
	}
	return false;
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

Future<Void> createBucket_gcs_impl(Reference<GCSBlobStoreEndpoint> b, std::string bucket) {
	co_await b->requestRateWrite->getAllowance(1);

	bool exists = co_await b->bucketExists(bucket);
	if (exists) {
		co_return;
	}

	if (b->projectId.empty()) {
		TraceEvent(SevError, "GCSBucketCreateMissingProject")
		    .detail("Bucket", bucket)
		    .detail("Hint", "Set gcs_project_id (or gcspid) URL parameter");
		throw backup_invalid_url();
	}

	// GCS XML API accepts the same PUT request as S3 for bucket creation.
	// x-goog-project-id is added by setRequestHeaders on every request.
	std::string resource = b->constructResourcePath(bucket, "");
	HTTP::Headers headers;
	Reference<HTTP::IncomingResponse> r =
	    co_await b->doRequest("PUT", resource, headers, nullptr, 0, { 200, 409 });
}

Future<Void> GCSBlobStoreEndpoint::createBucket(std::string const& bucket) {
	return createBucket_gcs_impl(Reference<GCSBlobStoreEndpoint>::addRef(this), bucket);
}
