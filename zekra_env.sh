# ZEKRA environment for this Jetson (crc32, one-Jetson/4-node setup)
#
# IMPORTANT: this must be SOURCED, not executed, so the exports land in your
# current shell (the one you'll run launch.py from) rather than a subshell
# that exits and throws them away:
#
#   source zekra_env.sh
#
# Do this AFTER killing any already-running nodes, and BEFORE `python3 launch.py`,
# since launch.py's spawned nodes inherit whatever is exported in this shell at
# the moment you run it.

export WORK=~/zekra_work

# --- every node ---
export ZEKRA_VERIFIER_MODE=real
export ZEKRA_VERIFIER_BIN=~/ZEKRA_S/ZEKRA/jsnark/libsnark/build/libsnark/jsnark_interface/run_verifier_only
export ZEKRA_AUTHORITY_PUBKEY=b2ecf0165759bce8f404d8320b8731bab8cdd23cb14133c0db00fdf1f71dd96d
export FLASK_DEBUG=0

# --- prover-capable nodes ---
export ZEKRA_PROGRAM_DIR=~/ZEKRA_S/ZEKRA/embench-iot-applications
export ZEKRA_FORMATTER=~/ZEKRA_S/ZEKRA/scripts/circuit_input_formatter.py
export ZEKRA_WORK_DIR=~/zekra_work_multi
export ZEKRA_JSNARK_JAR=~/ZEKRA_S/ZEKRA/xjsnark_backend.jar
export ZEKRA_CIRCUIT_INPUT_DIR=$WORK/inputs
export ZEKRA_CIRCUIT_OUTPUT_DIR=$WORK/out
export ZEKRA_JAVA_CP=~/ZEKRA_S/ZEKRA/bin:~/ZEKRA_S/ZEKRA/xjsnark_backend.jar
export ZEKRA_JAVA_CLASS=xjsnark.zekra.zekra
export ZEKRA_JAVA_DIR=~/ZEKRA_S/ZEKRA
export ZEKRA_PROVER_BIN=~/ZEKRA_S/ZEKRA/jsnark/libsnark/build/libsnark/jsnark_interface/run_prover_raw
export ZEKRA_ARITH=$WORK/out/zekra.arith
export ZEKRA_PROVING_KEY=$WORK/keys/proving_key_raw.bin
export ZEKRA_CIRCUIT_METADATA=$WORK/meta/circuit_metadata.bin

echo "ZEKRA env loaded. Verify with: env | grep ZEKRA"
