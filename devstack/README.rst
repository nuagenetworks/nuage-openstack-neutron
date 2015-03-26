========================
Devstack external plugin
========================

Add and set the following in your local.conf/localrc file:


enable_plugin nuage https://github.com/nuage-networks/nuage-openstack-neutron.git

Q_PLUGIN=nuage

Required settings
-----------------

# nuagenetlib repository
# e.g. NUAGENETLIB_REPO=http://github.mv.usa.alcatel.com/OpenStack/nuagenetlib.git

NUAGENETLIB_REPO


# branch to use
# e.g. NUAGENETLIB_BRANCH=master

NUAGENETLIB_BRANCH


# IP Address and Port of VSD
# e.g. NUAGE_VSD_SERVERS=172.31.4.211:8443

NUAGE_VSD_SERVERS


# Username and password of VSD for authentication
# e.g. NUAGE_VSD_SERVER_AUTH=uname:psswd

NUAGE_VSD_SERVER_AUTH


# Organization name in which VSD will orchestrate network resources using openstack
# e.g. NUAGE_VSD_ORGANIZATION=csp

NUAGE_VSD_ORGANIZATION


# Boolean for SSL connection with VSD server
# e.g. NUAGE_VSD_SERVER_SSL=True

NUAGE_VSD_SERVER_SSL


# Nuage provided base uri to reach out to VSD
# e.g. NUAGE_VSD_BASE_URI=/nuage/api/v3_0

NUAGE_VSD_BASE_URI


# Nuage provided uri for initial authorization to access VSD
# e.g. NUAGE_VSD_AUTH_RESOURCE=/me

NUAGE_VSD_AUTH_RESOURCE


# Default Network partition in which VSD will orchestrate network resources using openstack
# e.g. NUAGE_VSD_DEF_NETPART_NAME=test-netpartition

NUAGE_VSD_DEF_NETPART_NAME


# OVS bridge to use by nova
# e.g. NOVA_OVS_BRIDGE=alubr0

NOVA_OVS_BRIDGE

