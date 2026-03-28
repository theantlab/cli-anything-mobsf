#!/bin/bash
# ObjectionPatch.sh — Intelligent objection patching
#
# When run inside an analysis directory (from cli-anything-mobsf analyse),
# uses analysis artifacts to guide patching decisions automatically.
# Otherwise falls back to manual flag-based operation.
#
# Usage:
#   ObjectionPatch.sh -d <analysis_dir> -a <apk_name> [-v version] [-t target] [-2] [-N] [-D] [-n]
#
# Intelligent mode (inside analysis directory):
#   ObjectionPatch.sh -d ./bradesco_analysis -a bradesco
#
# Manual mode (original behaviour):
#   ObjectionPatch.sh -d ./output -a sampleApk -v 17.8.2 -t com.example.MainActivity -2

set -euo pipefail

ROOTDIR=""
APKROOT=""
VERSION=""
TARGETCLASS=""
USE_AAPT2=""
NET_SEC_CONFIG=""
SKIP_RESOURCES=""
IGNORE_NATIVELIBS=""
ENABLE_DEBUG=""
CONCURRENCY=""
GADGET_CONFIG=""
SCRIPTNAME="$(basename "$0")"

usage() {
    cat << EOF
Usage: ${SCRIPTNAME} [options]

REQUIRED:
  -d|--directory          Analysis/output directory
  -a|--apk               APK name (without .apk extension)

OPTIONAL:
  -v|--version            Frida gadget version (auto-detected if omitted)
  -t|--target             Target class to patch
  -2|--use-aapt2          Use aapt2 (default in intelligent mode)
  -N|--net-sec-config     Inject network_security_config.xml for user CA trust
  -D|--skip-resources     Skip resource decoding
  -n|--ignore-nativelibs  Don't modify extractNativeLibs flag
  -d|--enable-debug       Set android:debuggable to true
  -j|--concurrency        Thread limit for repackaging (use 1 for large APKs)
  -c|--gadget-config      Path to Frida gadget config JSON

If the directory contains analysis artifacts (mobsf/, attack_surface/),
the Python intelligent patcher is used automatically.

Example:
  ${SCRIPTNAME} -d ./bradesco_analysis -a bradesco
  ${SCRIPTNAME} -d . -a sampleApk -v 17.8.2 -t com.example.MainActivity -2
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--directory)    ROOTDIR="$2"; shift 2 ;;
        -a|--apk)          APKROOT="$2"; shift 2 ;;
        -v|--version)      VERSION="$2"; shift 2 ;;
        -t|--target)       TARGETCLASS="$2"; shift 2 ;;
        -2|--use-aapt2)    USE_AAPT2="1"; shift ;;
        -N|--net-sec-config) NET_SEC_CONFIG="1"; shift ;;
        -D|--skip-resources) SKIP_RESOURCES="1"; shift ;;
        -n|--ignore-nativelibs) IGNORE_NATIVELIBS="1"; shift ;;
        --enable-debug)    ENABLE_DEBUG="1"; shift ;;
        -j|--concurrency)  CONCURRENCY="$2"; shift 2 ;;
        -c|--gadget-config) GADGET_CONFIG="$2"; shift 2 ;;
        -h|--help)         usage; exit 0 ;;
        *)                 echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

if [[ -z "${ROOTDIR}" ]] || [[ -z "${APKROOT}" ]]; then
    echo "${SCRIPTNAME}: Missing required arguments" >&2
    usage
    exit 1
fi

# ── Intelligent mode: use Python patcher if analysis artifacts exist ──
if [[ -d "${ROOTDIR}/mobsf" ]] || [[ -d "${ROOTDIR}/attack_surface" ]]; then
    echo "Analysis artifacts detected — using intelligent patcher"

    # Find the APK
    APK_PATH=""
    for candidate in \
        "${APKROOT}.apk" \
        "${ROOTDIR}/${APKROOT}.apk" \
        "${ROOTDIR}/apktool/${APKROOT}.apk" \
        "${ROOTDIR}/repackage/${APKROOT}.apk"; do
        if [[ -f "${candidate}" ]]; then
            APK_PATH="${candidate}"
            break
        fi
    done

    if [[ -z "${APK_PATH}" ]]; then
        echo "Error: Could not find ${APKROOT}.apk" >&2
        exit 1
    fi

    python3 -c "
from cli_anything.mobsf.core.objection_patcher import ObjectionPatcher
patcher = ObjectionPatcher('${ROOTDIR}', '${APK_PATH}')
patcher.plan()
patcher.patch('${ROOTDIR}/objection')
"
    exit $?
fi

# ── Manual mode: direct objection patchapk ────────────────────────────
echo "Manual mode — no analysis artifacts found"

# Auto-detect Frida version if not provided
if [[ -z "${VERSION}" ]]; then
    VERSION="$(frida --version 2>/dev/null || echo '')"
    if [[ -z "${VERSION}" ]]; then
        echo "Error: Could not detect Frida version. Install frida or use -v flag." >&2
        exit 1
    fi
    echo "Detected Frida version: ${VERSION}"
fi

mkdir -p "${ROOTDIR}/objection"
cp "${APKROOT}.apk" "${ROOTDIR}/objection/"

CMD="objection patchapk --source ${ROOTDIR}/objection/${APKROOT}.apk --gadget-version ${VERSION} -a arm64-v8a"

[[ -n "${TARGETCLASS}" ]]     && CMD="${CMD} --target-class ${TARGETCLASS}"
[[ -n "${USE_AAPT2}" ]]       && CMD="${CMD} --use-aapt2"
[[ -n "${NET_SEC_CONFIG}" ]]  && CMD="${CMD} --network-security-config"
[[ -n "${SKIP_RESOURCES}" ]]  && CMD="${CMD} --skip-resources"
[[ -n "${IGNORE_NATIVELIBS}" ]] && CMD="${CMD} --ignore-nativelibs"
[[ -n "${ENABLE_DEBUG}" ]]    && CMD="${CMD} --enable-debug"
[[ -n "${CONCURRENCY}" ]]     && CMD="${CMD} --fix-concurrency-to ${CONCURRENCY}"
[[ -n "${GADGET_CONFIG}" ]]   && CMD="${CMD} --gadget-config ${GADGET_CONFIG}"

echo ""
echo "Command: ${CMD}"
echo ""
echo "...objection processing"

cd "${ROOTDIR}/objection"
eval "${CMD}"
