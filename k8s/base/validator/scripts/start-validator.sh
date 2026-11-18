#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Starts the Lighthouse validator client.
#
# --init-slashing-protection is the single most dangerous flag in a validator
# setup: if the slashing-protection DB is ever lost (wrong PVC, restored
# backup, new cluster) the flag silently creates an empty one and the
# validator will happily sign conflicting messages. So it is never written
# into the manifest; it is toggled through an explicit, reviewed ConfigMap
# value for the first boot of a brand-new validator set only.
# -----------------------------------------------------------------------------
set -euo pipefail

extra_args=()
if [[ "${INIT_SLASHING_PROTECTION:-false}" == "true" ]]; then
  echo "start-validator: WARNING: --init-slashing-protection is enabled." >&2
  echo "start-validator: set INIT_SLASHING_PROTECTION=false immediately after the first successful start." >&2
  extra_args+=(--init-slashing-protection)
fi

exec lighthouse "$@" "${extra_args[@]}"
