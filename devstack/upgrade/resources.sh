#!/usr/bin/env bash

set -x
set -e

source $GRENADE_DIR/grenaderc
source $GRENADE_DIR/functions

PROJECT=nuage-openstack-neutron

function create_resources {
    local NETPART_NAME
    local NETPART
    local NET1
    local NET2
    local SUBNET1
    local SUBNET2
    local PORT1
    local PORT2

    NETPART_NAME=$(cat /dev/urandom | tr -dc 'a-zA-Z' | fold -w 32 | head -n 1)
    NETPART1=$(neutron  --os-cloud devstack-admin nuage-netpartition-create ${NETPART_NAME} -c id -f value)
    resource_save ${PROJECT} netpartition_nuage ${NETPART1}

    NET1=$(openstack  --os-cloud devstack-admin network create -f value -c id net-nuage)
    resource_save ${PROJECT} net_nuage ${NET1}

    SUBNET1=$(openstack  --os-cloud devstack-admin subnet create -f value -c id --ip-version 4 --subnet-range 192.2.0.0/24 --network ${NET1} subnet1)
    resource_save ${PROJECT} subnet1 ${SUBNET1}

    PORT1=$(neutron  --os-cloud devstack-admin port-create -f value -c id --name port1 ${NET1})
    resource_save ${PROJECT} port1 ${PORT1}

    NET2=$(openstack  --os-cloud devstack-admin network create -f value -c id net_netpart)
    resource_save ${PROJECT} net_netpart ${NET2}

    SUBNET2=$(neutron  --os-cloud devstack-admin subnet-create -f value -c id --ip-version 4 --name subnet2 ${NET2} 192.3.0.0/24 --net-partition ${NETPART1})
    resource_save ${PROJECT} subnet2 ${SUBNET2}

    PORT2=$(neutron  --os-cloud devstack-admin port-create -f value -c id --name port2 ${NET2})
    resource_save ${PROJECT} port2 ${PORT2}
}

function verify_resources {

    local net_type
    local NETPART
    local NET1
    local NET2
    local PORT1
    local PORT2

    NETPART=$(resource_get ${PROJECT} netpartition_nuage)
    netpart_name=$(neutron  --os-cloud devstack-admin nuage-netpartition-show $NETPART -c name -f value)

    NET1=$(resource_get ${PROJECT} net_nuage)
    net_type=$(openstack  --os-cloud devstack-admin network show -f value -c provider:network_type ${NET1})
    test "${net_type}" = vxlan


    NET2=$(resource_get ${PROJECT} net_netpart)
    net_type=$(openstack  --os-cloud devstack-admin network show -f value -c provider:network_type ${NET2})
    test "${net_type}" = vxlan

    PORT1=$(resource_get ${PROJECT} port1)
    PORT2=$(resource_get ${PROJECT} port2)
}

function destroy {

    local NETPART
    local NET1
    local NET2
    local PORT1
    local PORT2

    PORT1=$(resource_get ${PROJECT} port1)
    openstack  --os-cloud devstack-admin port delete $PORT1

    PORT2=$(resource_get ${PROJECT} port2)
    openstack  --os-cloud devstack-admin port delete $PORT2

    NET1=$(resource_get ${PROJECT} net_nuage)
    openstack  --os-cloud devstack-admin network delete $NET1

    NET2=$(resource_get ${PROJECT} net_netpart)
    openstack  --os-cloud devstack-admin network delete $NET2

    NETPART=$(resource_get ${PROJECT} netpartition_nuage)
    neutron  --os-cloud devstack-admin nuage-netpartition-delete $NETPART
}


case $1 in
    "create")
        create_resources
        ;;
    "verify")
        verify_resources
        ;;
    "destroy")
        destroy
        ;;
esac

