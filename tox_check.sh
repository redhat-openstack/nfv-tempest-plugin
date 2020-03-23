#!/bin/bash
set -euxo pipefail
export TOXENV="pep8,py27"

python -m tox

