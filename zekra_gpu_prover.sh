#!/usr/bin/env bash
# Drop-in replacement for run_prover_raw. Called by zekra_integration.py as:
#   <arith> <proving_key> <metadata> <witness> <output_dir>
# The proving_key argument is ignored in favor of this program's own
# prepared/proving_key_raw_compact.bin -- the raw key path zekra_integration.py
# passes is the *uncompacted* key (keys/proving_key_raw.bin), which the GPU
# binary doesn't read; the compact/prepared form lives next to it.
#
# Uses run_prover_v12_concurrent_msm (SHA-256 9eb48ddf...), the canonical GPU
# prover per GPU_ZEKRA's own docs, with ZEKRA_CONCURRENT_GPU_MSM=0 -- the
# documented production setting -- validated against this exact key/circuit
# on 2026-09-15 (ACCEPTED, 259-byte proof, matches v10's output).
set -euo pipefail

ARITH=$1; META=$3; WITNESS=$4; OUTDIR=$5
WD=$(dirname "$(dirname "$ARITH")")   # .../<program_id>/out/zekra.arith -> .../<program_id>
PREP="$WD/prepared"

if [[ ! -s "$PREP/proving_key_raw_compact.bin" ]]; then
  echo "zekra_gpu_prover.sh: no GPU-prepared bundle at $PREP -- refusing (no CPU fallback wired up yet)" >&2
  exit 1
fi

mkdir -p "$OUTDIR"

exec env \
  ZEKRA_FLAT_CS_FILE="$PREP/flat_cs.bin" \
  ZEKRA_FLAT_CS_DIRECT=1 \
  ZEKRA_FLAT_CS_DIRECT_CROSSCHECK=0 \
  ZEKRA_FLAT_CS_HASH_INDEX="$PREP/flat_cs_hash_index.bin" \
  ZEKRA_FLAT_CS_COMPACT_PK=1 \
  ZEKRA_QAP_CONSTRAINT_BACKEND=fused \
  ZEKRA_QAP_CONSTRAINT_CROSSCHECK=0 \
  ZEKRA_WITNESS_PROGRAM="$PREP/witness_program.bin" \
  ZEKRA_WITNESS_CROSSCHECK=0 \
  ZEKRA_QAP_PIPELINE_BACKEND=device \
  ZEKRA_QAP_PIPELINE_CROSSCHECK=0 \
  ZEKRA_G2_BACKEND=gpu \
  ZEKRA_G2_SIDECAR="$PREP/g2_queries.sidecar" \
  ZEKRA_G2_SIDECAR_CROSSCHECK=0 \
  ZEKRA_G1_SIDECAR="$PREP/g1_queries.sidecar" \
  ZEKRA_G1_SIDECAR_CROSSCHECK=0 \
  ZEKRA_MSM_BACKEND=icicle \
  ZEKRA_NTT_BACKEND=icicle \
  ZEKRA_NTT_CROSSCHECK=0 \
  ZEKRA_DIVZ_BACKEND=optimized_cpu \
  ZEKRA_DIVZ_CROSSCHECK=0 \
  ZEKRA_CONCURRENT_GPU_MSM=0 \
  "${ZEKRA_GPU_PROVER_BIN:-$HOME/zekra_gpu_icicle/v12_concurrent_msm_build/run_prover_v12_concurrent_msm}" \
  "$ARITH" "$PREP/proving_key_raw_compact.bin" "$META" "$WITNESS" "$OUTDIR"
