#!/bin/bash
set -euxo pipefail
PY_INTERP=$(python -c 'import sys; print ("{}{}".format(sys.version_info[0], sys.version_info[1]))')
PY_VER=py$PY_INTERP
export TOXENV="pep8,$PY_VER"

python -m tox
