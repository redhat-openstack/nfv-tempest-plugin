#!/bin/bash
set -euxo pipefail
export TOXENV="pep8,py{37,27}"

python -m tox

