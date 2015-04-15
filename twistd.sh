#! /bin/bash

THISDIR="$( cd $(dirname $0); pwd)"
SCRIPT="$THISDIR/$(basename $0)"
PYENV="$THISDIR/pyenv"

# Activate python virtualenv.
. "$PYENV/bin/activate"
# Tell the system where any extra shared libraries live.
export LD_LIBRARY_PATH=/usr/local/lib64

twistd $@
