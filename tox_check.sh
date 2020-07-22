#!/bin/bash

set -euxo pipefail
export TOXENV="pep8,py27,py3"

show_help() {
    cat <<-END
    Usage:
    ------
    The tox_check script will execute tox.ini configuration and provided TOXENV parameters.
    By default it will execute - pip8, py27, py3

    The user is able to override the parameters by specifying the --env flag.

    -h | --help
      Display help.
    -e | --env
      Override the tox environment definition.
      --env pep8,py3
END
}

while (( $# )); do
    case $1 in
	-h|--help)
	    show_help
	    exit 0;;
	-e|--env)
	    if [ -n "$2" ]; then
		export TOXENV=$2
		shift
	    fi;;
	*) # Default case: If no more options then break out of the loop.
	    break
    esac
    shift
done

python -m tox
