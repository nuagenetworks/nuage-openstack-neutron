========================
Devstack external plugin
========================

Add and set the following in your local.conf/localrc file:


enable_plugin nuage https://github.com/nuage-networks/nuage-openstack-neutron.git

Q_PLUGIN=nuage

Required settings
-----------------

::

    # nuagenetlib repository
    NUAGENETLIB_REPO=http://github.mv.usa.alcatel.com/OpenStack/nuagenetlib.git

    # branch to use
    NUAGENETLIB_BRANCH=master

    # IP Address and Port of VSD
    NUAGE_VSD_SERVERS=172.31.4.211:8443

    # Username and password of VSD for authentication
    NUAGE_VSD_SERVER_AUTH=uname:psswd

    # Organization name in which VSD will orchestrate network resources using openstack
    NUAGE_VSD_ORGANIZATION=csp

    # Boolean for SSL connection with VSD server
    NUAGE_VSD_SERVER_SSL=True

    # Nuage provided base uri to reach out to VSD
    NUAGE_VSD_BASE_URI=/nuage/api/v4_0

    # Nuage provided uri for initial authorization to access VSD
    NUAGE_VSD_AUTH_RESOURCE=/me

    # Default Network partition in which VSD will orchestrate network resources using openstack
    NUAGE_VSD_DEF_NETPART_NAME=test-netpartition

    # OVS bridge to use by nova
    NOVA_OVS_BRIDGE=alubr0


Enabling LBaaS
--------------
Add following settings to your local.conf::

    enable_service q-lbaasv2
    enable_plugin neutron-lbaas https://git.openstack.org/openstack/neutron-lbaas
    NEUTRON_LBAAS_SERVICE_PROVIDERV2=LOADBALANCERV2:Haproxy:neutron_lbaas.drivers.haproxy.plugin_driver.HaproxyOnHostPluginDriver:default


Enabling BGPVPN
---------------
Add the following settings to your local.conf::

    enable_plugin networking-bgpvpn git://git.openstack.org/openstack/networking-bgpvpn.git
    NETWORKING_BGPVPN_DRIVER="BGPVPN:Nuage:nuage_neutron.bgpvpn.services.service_drivers.driver.NuageBGPVPNDriver:default"
