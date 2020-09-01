echo "*********************************************************************"
echo "Begin $0"
echo "*********************************************************************"

set -o xtrace

# gridinv: We prepare venv for further projects upgrade.
# devstack @ussuri will attempt to do this via python3 -mvenv
# which fails on centos7 with python3.6.
# This is needed only on migration T -> U
install_infra_venv() {
    local PIP_VIRTUAL_ENV="$REQUIREMENTS_DIR/.venv"
    virtualenv $PIP_VIRTUAL_ENV
    $PIP_VIRTUAL_ENV/bin/pip install -U pbr
    $PIP_VIRTUAL_ENV/bin/pip install $REQUIREMENTS_DIR
    unset PIP_VIRTUAL_ENV
}

# Set for DevStack compatibility

source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions
source $TARGET_DEVSTACK_DIR/stackrc

# Get functions from current DevStack
source $TARGET_DEVSTACK_DIR/inc/python

# install plugin
setup_develop $TARGET_RELEASE_DIR/nuage-openstack-neutron

# setup infra venv so that further upgrade does not fail
install_infra_venv

# gridinv: hack to get upgrade working for U on centos7
sed -i 's/python3-mod_wsgi/mod_wsgi/g' $TARGET_RELEASE_DIR/devstack/lib/apache

set +x
set +o xtrace
echo "*********************************************************************"
echo "SUCCESS: End $0"
echo "*********************************************************************"
