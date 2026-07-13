#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHON_BIN="${PYTHON_BIN:-python3}"

RUN_SOURCE_CANDIDATES="${RUN_SOURCE_CANDIDATES:-1}"
RUN_SOURCE_RISK="${RUN_SOURCE_RISK:-1}"
RUN_SINK_PATHS="${RUN_SINK_PATHS:-1}"
RUN_CONTEXT_EXPANDER="${RUN_CONTEXT_EXPANDER:-1}"
RUN_INTERPROCEDURAL_CONTEXT="${RUN_INTERPROCEDURAL_CONTEXT:-1}"
RUN_SINK_VULN="${RUN_SINK_VULN:-1}"

run_step() {
  local enabled="$1"
  local title="$2"
  local env_var_name="$3"
  local env_file="$4"
  local module="$5"

  if [[ "${enabled}" != "1" ]]; then
    printf '[skip] %s\n' "${title}"
    return 0
  fi

  if [[ ! -f "${env_file}" ]]; then
    printf '[error] %s env file not found: %s\n' "${title}" "${env_file}" >&2
    return 1
  fi

  printf '\n==> %s\n' "${title}"
  printf '    env: %s\n' "${env_file}"
  (
    cd "${ROOT_DIR}"
    env "${env_var_name}=${env_file}" "${PYTHON_BIN}" "${module}"
  )
}

printf 'CPG analysis pipeline\n'
printf 'root: %s\n' "${ROOT_DIR}"
printf 'python: %s\n' "${PYTHON_BIN}"

run_step \
  "${RUN_SOURCE_CANDIDATES}" \
  "Find source candidates" \
  "SOURCES_CANDIDATE_ENV_FILE" \
  "${ROOT_DIR}/config/sources_candidate_finder.env" \
  "source_candidate_finder.py"

run_step \
  "${RUN_SOURCE_RISK}" \
  "Analyze source risk with LLM" \
  "SOURCE_RISK_ENV_FILE" \
  "${ROOT_DIR}/config/source_risk_model.env" \
  "source_risk_model.py"

run_step \
  "${RUN_SINK_PATHS}" \
  "Find sink paths" \
  "SINK_PATH_ENV_FILE" \
  "${ROOT_DIR}/config/sink_path_finder.env" \
  "sink_path_finder.py"

run_step \
  "${RUN_CONTEXT_EXPANDER}" \
  "Expand deterministic context" \
  "CONTEXT_EXPANDER_ENV_FILE" \
  "${ROOT_DIR}/config/context_expander.env" \
  "context_expander.py"

run_step \
  "${RUN_INTERPROCEDURAL_CONTEXT}" \
  "Build interprocedural context" \
  "INTERPROCEDURAL_CONTEXT_ENV_FILE" \
  "${ROOT_DIR}/config/interprocedural_context.env" \
  "interprocedural_context.py"

run_step \
  "${RUN_SINK_VULN}" \
  "Analyze source-to-sink vulnerabilities with LLM" \
  "SINK_VULN_ENV_FILE" \
  "${ROOT_DIR}/config/sink_vuln_model.env" \
  "sink_vuln_model.py"

printf '\nPipeline finished successfully.\n'
