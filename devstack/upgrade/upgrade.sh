#! /usr/bin/env bash

source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions
source $TARGET_DEVSTACK_DIR/stackrc

set -o errexit
set -x

TOP_DIR=$TARGET_DEVSTACK_DIR

# install plugin
setup_develop $TARGET_RELEASE_DIR/nuage-openstack-neutron


set +x
set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End $0"
echo "*********************************************************************"


