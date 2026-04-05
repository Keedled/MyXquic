#!/usr/bin/env bash

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_BIN="${ROOT_DIR}/build/chunk_transfer/chunk_client"
SERVER_BIN="${ROOT_DIR}/build/chunk_transfer/chunk_server"

PORT_BASE="${PORT_BASE:-9451}"
ADDR="${ADDR:-127.0.0.1}"
HOST="${HOST:-localhost}"
CHUNK_SIZE="${CHUNK_SIZE:-524288}"
FILE_SIZE_MIB="${FILE_SIZE_MIB:-8}"
TIMEOUT_SEC="${TIMEOUT_SEC:-15}"
RETRIES="${RETRIES:-1}"
LOG_LEVEL="${LOG_LEVEL:-2}"
KEEP_WORK_DIR="${KEEP_WORK_DIR:-0}"

if [[ "$#" -gt 0 ]]; then
    CONCURRENCY_LIST=("$@")
else
    CONCURRENCY_LIST=(1 4 8)
fi

TMP_ROOT="${TMPDIR:-/tmp}"
WORK_DIR="$(mktemp -d "${TMP_ROOT%/}/chunk-transfer-test.XXXXXX")"
INPUT_FILE="${WORK_DIR}/input.bin"
INPUT_HASH=""
SERVER_PID=""
PRESERVE_WORK_DIR=0

hash_file() {
    local file_path="$1"

    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${file_path}" | awk '{print $1}'
        return
    fi

    if command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${file_path}" | awk '{print $1}'
        return
    fi

    echo "missing sha256 tool" >&2
    exit 1
}

stop_server() {
    if [[ -n "${SERVER_PID}" ]] && kill -0 "${SERVER_PID}" >/dev/null 2>&1; then
        kill "${SERVER_PID}" >/dev/null 2>&1 || true
        wait "${SERVER_PID}" 2>/dev/null || true
    fi
    SERVER_PID=""
}

cleanup() {
    stop_server

    if [[ "${KEEP_WORK_DIR}" == "1" || "${PRESERVE_WORK_DIR}" == "1" ]]; then
        echo "preserving work dir: ${WORK_DIR}"
    else
        rm -rf "${WORK_DIR}"
    fi
}

trap 'PRESERVE_WORK_DIR=1' ERR
trap cleanup EXIT

if [[ ! -x "${CLIENT_BIN}" || ! -x "${SERVER_BIN}" ]]; then
    echo "missing built targets:"
    echo "  ${CLIENT_BIN}"
    echo "  ${SERVER_BIN}"
    echo "build them first with:"
    echo "  cmake -DXQC_ENABLE_TESTING=1 -B build"
    echo "  cmake --build build --target chunk_client chunk_server -j4"
    exit 1
fi

echo "== chunk_transfer concurrency test =="
echo "root          : ${ROOT_DIR}"
echo "client        : ${CLIENT_BIN}"
echo "server        : ${SERVER_BIN}"
echo "addr          : ${ADDR}"
echo "host          : ${HOST}"
echo "chunk size    : ${CHUNK_SIZE}"
echo "file size     : ${FILE_SIZE_MIB} MiB"
echo "concurrency   : ${CONCURRENCY_LIST[*]}"
echo "work dir      : ${WORK_DIR}"

dd if=/dev/urandom of="${INPUT_FILE}" bs=1048576 count="${FILE_SIZE_MIB}" status=none
INPUT_HASH="$(hash_file "${INPUT_FILE}")"

echo "input hash    : ${INPUT_HASH}"
echo

run_one_case() {
    local concurrency="$1"
    local port="$2"
    local output_file="${WORK_DIR}/output_j${concurrency}.bin"
    local server_log="${WORK_DIR}/server_j${concurrency}.log"
    local client_log="${WORK_DIR}/client_j${concurrency}.log"
    local output_hash=""

    rm -f "${output_file}" "${server_log}" "${client_log}"

    echo "-- test j=${concurrency}, port=${port} --"
    "${SERVER_BIN}" -a "${ADDR}" -p "${port}" -w "${output_file}" -t "${TIMEOUT_SEC}" -l "${LOG_LEVEL}" \
        >"${server_log}" 2>&1 &
    SERVER_PID="$!"

    sleep 1

    "${CLIENT_BIN}" -a "${ADDR}" -p "${port}" -h "${HOST}" -i "${INPUT_FILE}" \
        -k "${CHUNK_SIZE}" -j "${concurrency}" -r "${RETRIES}" -t "${TIMEOUT_SEC}" -l "${LOG_LEVEL}" \
        >"${client_log}" 2>&1

    output_hash="$(hash_file "${output_file}")"
    if [[ "${output_hash}" != "${INPUT_HASH}" ]]; then
        echo "hash mismatch for j=${concurrency}" >&2
        echo "input : ${INPUT_HASH}" >&2
        echo "output: ${output_hash}" >&2
        echo "client log: ${client_log}" >&2
        echo "server log: ${server_log}" >&2
        exit 1
    fi

    echo "hash ok       : ${output_hash}"
    echo "client log    : ${client_log}"
    echo "server log    : ${server_log}"
    echo

    stop_server
}

for index in "${!CONCURRENCY_LIST[@]}"; do
    run_one_case "${CONCURRENCY_LIST[$index]}" "$((PORT_BASE + index))"
done

echo "all concurrency cases passed"
