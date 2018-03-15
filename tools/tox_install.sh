#!/usr/bin/env bash

# Many of neutron's repos suffer from the problem of depending on neutron,
# but it not existing on pypi. This ensures its installed into the test environment.
set -ex

ZUUL_CLONER=/usr/zuul-env/bin/zuul-cloner
UPPER_CONSTRAINTS_FILE=${UPPER_CONSTRAINTS_FILE:-unconstrained}

install_cmd="pip install"

if [ "$UPPER_CONSTRAINTS_FILE" != "unconstrained" ]; then
    install_cmd="$install_cmd -c$UPPER_CONSTRAINTS_FILE"
fi

# Install the rest of the requirements as normal
$install_cmd -U $*

exit $?
