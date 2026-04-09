#!/usr/bin/env bash
#
# Functions for dealing w/ Azure Blob Storage
#
# Here is how to use this fixture:
#
# - set AZURE_STORAGE_ACCOUNT, AZURE_STORAGE_KEY, and AZURE_STORAGE_CONTAINER
#
#  # First source this fixture.
#  if ! source "${cwd}/azure_fixture.sh"; then
#    err "Failed to source azure_fixture.sh"
#    exit 1
#  fi
#  if ! TEST_SCRATCH_DIR=$( create_azure_dir "${scratch_dir}" ); then
#    err "Failed creating local azure_dir"
#    exit 1
#  fi
#  readonly TEST_SCRATCH_DIR
#  if ! azure_output=$(azure_setup "${build_dir}" "${TEST_SCRATCH_DIR}"); then
#    err "Failed azure_setup"
#    exit 1
#  fi
#  IFS=$'\n' read -r -d '' account host bucket blob_credentials_file <<< "${azure_output}" || true
#  ...
#  # When done, call shutdown_azure
#  shutdown_azure "${TEST_SCRATCH_DIR}"
#

# Cleanup any mess we've made. For calling from signal trap on exit.
# $1 The azure scratch directory to clean up on exit.
function shutdown_azure {
  local local_scratch_dir="${1}"
  if [[ -d "${local_scratch_dir}" ]]; then
    rm -rf "${local_scratch_dir}"
  fi
}

# Create directory for azure test to use writing temporary data.
# $1 Directory where we want to write data and logs.
function create_azure_dir {
  local dir="${1}"
  local azure_dir
  azure_dir=$(mktemp -d "${dir}/azure.$$.XXXX")
  if [[ ! -d "${azure_dir}" ]]; then
    echo "ERROR: Failed create of azure directory ${azure_dir}" >&2
    return 1
  fi
  echo "${azure_dir}"
}

# Write out blob_credentials for Azure
# $1 The storage account name
# $2 The shared key (base64-encoded)
# $3 Hostname for Azure storage
# $4 The scratch dir to write the blob credentials file into
# Echos the blob_credentials file path.
function write_azure_blob_credentials {
  local account_name="${1}"
  local shared_key="${2}"
  local host="${3}"
  local dir="${4}"
  # Credential file key is "@host" (matching the IBlobStoreEndpoint convention)
  local cred_key="@${host}"
  blob_credentials_str="{\"accounts\": { \"${cred_key}\": {\"secret\": \"${shared_key}\"}}}"
  local blob_credentials_file="${dir}/blob_credentials.json"
  echo "${blob_credentials_str}" > "${blob_credentials_file}"
  echo "${blob_credentials_file}"
}

# Set up Azure Blob Storage access.
# $1 build_dir
# $2 azure_dir (created by create_azure_dir)
# Returns: account_name, host, container, blob_credentials_file (newline-separated)
function azure_setup {
  if [ -z "${AZURE_STORAGE_ACCOUNT:-}" ]; then
    echo "Error: AZURE_STORAGE_ACCOUNT is not set." >&2
    exit 1
  fi
  if [ -z "${AZURE_STORAGE_KEY:-}" ]; then
    echo "Error: AZURE_STORAGE_KEY is not set." >&2
    exit 1
  fi
  if [ -z "${AZURE_STORAGE_CONTAINER:-}" ]; then
    echo "Error: AZURE_STORAGE_CONTAINER is not set." >&2
    exit 1
  fi
  local local_build_dir="${1}"
  local local_azure_dir="${2}"

  local account="${AZURE_STORAGE_ACCOUNT}"
  local host="${account}.blob.core.windows.net"
  local container="${AZURE_STORAGE_CONTAINER}"

  local blob_credentials_file
  if ! blob_credentials_file=$(write_azure_blob_credentials "${account}" "${AZURE_STORAGE_KEY}" "${host}" "${local_azure_dir}"); then
    echo "Failed to write credentials file" >&2
    exit 1
  fi

  # Output: account_prefix (for URL), host, container, credentials_file
  printf "%s\n%s\n%s\n%s" "${account}" "${host}" "${container}" "${blob_credentials_file}"
}
