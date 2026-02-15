#!/usr/bin/env bash
set -euo pipefail

sarif_file="${TRIVY_SARIF_FILE:-}"
scan_outcome="${TRIVY_SCAN_OUTCOME:-}"

if [[ -z "${sarif_file}" ]]; then
  echo "TRIVY_SARIF_FILE is required" >&2
  exit 2
fi

if [[ -s "${sarif_file}" ]]; then
  echo "found=true" >> "${GITHUB_OUTPUT}"
  echo "sarif_file=${sarif_file}" >> "${GITHUB_OUTPUT}"
  exit 0
fi

echo "::warning::Trivy did not create ${sarif_file} (scan_outcome=${scan_outcome})."

if [[ "${scan_outcome}" == "success" ]]; then
  # shellcheck disable=SC2016 # '$schema' is a literal SARIF key.
  printf '%s\n' '{"version":"2.1.0","$schema":"https://json.schemastore.org/sarif-2.1.0.json","runs":[{"tool":{"driver":{"name":"Trivy"}},"results":[]}]}' > "${sarif_file}"
  echo "::notice::Created an empty SARIF so GitHub code scanning stays in sync."
  echo "found=true" >> "${GITHUB_OUTPUT}"
  echo "sarif_file=${sarif_file}" >> "${GITHUB_OUTPUT}"
  exit 0
fi

echo "found=false" >> "${GITHUB_OUTPUT}"
echo "sarif_file=" >> "${GITHUB_OUTPUT}"
