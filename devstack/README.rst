========================
Devstack external plugin
========================

Add and set the following in your local.conf/localrc file:

enable_plugin nuage-openstack-neutron https://github.com/nuage-networks/nuage-openstack-neutron.git


Core plugin
-----------

Q_PLUGIN=nuage


ML2 mechanism driver
--------------------
Q_PLUGIN=ml2

Q_ML2_PLUGIN_MECHANISM_DRIVERS=nuage

Q_ML2_PLUGIN_EXT_DRIVERS=nuage_subnet,nuage_port,port_security


Required settings
=================

Please consult <this repo>/etc/neutron/plugins/nuage/plugin.ini.sample


Enabling dhcp agent
-------------------
Add following settings to your local.conf::

    enable_service q-dhcp
    NEUTRON_AGENT=nuagevrs

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

