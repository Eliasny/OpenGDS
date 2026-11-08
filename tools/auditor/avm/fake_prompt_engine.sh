#!/bin/sh
# A stand-in engine for test_avm_prompt: one test that asks the operator
# one step, the way gdsaudit does (engine.h operator prompts). It reads the
# answer from --prompts, sends it back as a note and exits 0 only if the
# answer line is exactly $WANT.
# SPDX-License-Identifier: MPL-2.0
prompts=
while [ $# -gt 0 ]; do
    case "$1" in
    --prompts) prompts=$2; shift ;;
    esac
    shift
done
[ "$prompts" = /dev/fd/4 ] || exit 2
ev() { printf '%s\n' "$1" >&3; }
ev '{"v":1,"ev":"run_started","profile":"server","target":"opc.tcp://fake:4840","planned":1,"allow_changes":false,"time":"2026-11-08T00:00:00Z"}'
ev '{"v":1,"ev":"test_started","n":1,"id":"T-1","clause":"x","title":"reset","changes":false,"operator":true}'
ev '{"v":1,"ev":"prompt","n":1,"seq":1,"text":"Press the reset button"}'
IFS= read -r line <&4 || line="(end of file)"
ev "{\"v\":1,\"ev\":\"note\",\"n\":1,\"text\":\"got: $line\"}"
ev '{"v":1,"ev":"prompt_answered","n":1,"seq":1,"answer":"fail","text":"lamp"}'
ev '{"v":1,"ev":"verdict","n":1,"id":"T-1","verdict":"fail","ms":1,"evidence":"operator"}'
rc=1
[ "$line" = "$WANT" ] && rc=0
ev "{\"v\":1,\"ev\":\"run_finished\",\"pass\":0,\"fail\":1,\"warn\":0,\"not_supported\":0,\"not_tested\":0,\"exit\":$rc,\"aborted\":false,\"time\":\"2026-11-08T00:00:01Z\"}"
echo "answer line: $line"
exit $rc
