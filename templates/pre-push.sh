#!/bin/sh
# @NAME@ — Doorman Jay, standing in git's own doorway.
#
# This file is WRITTEN by `install.py` with the paths of your machine.
# If you edit it by hand, the next `install.py` overwrites it.
#
# Switch it on for the whole machine with:
#     git config --global core.hooksPath "@FOLDER@"

PY="@PYTHON@"
REVIEWER="@FOLDER@/doorman_jay.py"
ME="@FOLDER@/@NAME@"

# If THIS repository brings its own hook, it is respected and runs first:
# `core.hooksPath` silently switches local hooks off, and tools like Git LFS
# or husky keep theirs in .git/hooks.
#
# 🔴 WHY --git-dir AND NOT --git-path hooks:
# with `core.hooksPath` set, `git rev-parse --git-path hooks` returns THIS VERY
# FOLDER. The hook would call itself and the push would hang forever. The
# comparison with "$ME" below is the belt, just in case.
GITDIR="$(git rev-parse --git-dir 2>/dev/null)"
LOCAL="$GITDIR/hooks/@NAME@"

# git hands over on stdin one line per reference about to be sent:
#   <local_ref> <local_sha> <remote_ref> <remote_sha>
# It is read ONCE: stdin cannot be read twice.
INPUT="$(cat)"

if [ -x "$LOCAL" ] && [ "$LOCAL" != "$ME" ]; then
    printf '%s\n' "$INPUT" | "$LOCAL" "$@" || exit $?
fi

printf '%s\n' "$INPUT" | "$PY" -I "$REVIEWER" --remote "$1" pre-push
exit $?
