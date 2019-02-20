# Copyright 2017 Nokia
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
#
import argparse
import errno
import json
import six
import socket
import sys
import time

from neutron.agent.linux.interface import OVSInterfaceDriver
from neutron_lib import exceptions


class NuageVMDriver(object):
    @classmethod
    def get_connected_socket(cls):
        OVSDB_IP = "localhost"
        OVSDB_PORT = 6640
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect((OVSDB_IP, OVSDB_PORT))
            print("echo Connected to the ovsdb \n")
        except socket.error:
            _, _, tb = sys.exc_info()
            six.reraise(exceptions.ServiceUnavailable,
                        exceptions.ServiceUnavailable(),
                        tb)
        return sock

    @classmethod
    def ovsdb_transaction(cls, msg, recv_msg=False, max_retries=5):
        print("echo sending ovsdb-query as: %s \n", msg)
        try:
            sock = cls.get_connected_socket()
            sock.sendall(msg)
            sock.shutdown(socket.SHUT_RDWR)
            if recv_msg:
                resp = sock.recv(4096)
                print("echo response from ovsdb-query was: %s \n", resp)
                try:
                    return json.loads(resp)
                except ValueError:
                    return None

        except Exception:
            ''' Retry 5 times every second '''
            if (socket.errno in [errno.EBUSY, errno.EAGAIN] and
                    max_retries > 0):
                time.sleep(1)
                print("echo retrying some error \n")
                return cls.ovsdb_transaction(
                    msg, recv_msg, max_retries=(max_retries - 1))
            else:
                raise

    @classmethod
    def plug(cls, port_id, device_name, mac_address,
             bridge):
        print("echo Nuage plugging port %(id)s:%(name)s on bridge %(bridge)s "
              "in namespace %(namespace)s \n",
              {'id': port_id,
               'name': device_name,
               'bridge': bridge,
               'namespace': None})

        # Formulate json object
        query = []
        # Operation 1
        query1 = {"id": 1,
                  "method": "transact",
                  "params": [
                      "Open_vSwitch", {
                          "op": "insert",
                          "table": "Nuage_Port_Table",
                          "row": {
                              "name": device_name
                          }
                      }
                  ]
                  }
        # Operation 2
        query2 = {"id": 2,
                  "method": "transact",
                  "params": [
                      "Open_vSwitch", {
                          "op": "insert",
                          "table": "Nuage_VM_Table",
                          "row": {
                              "vm_uuid": port_id
                          }
                      }
                  ]
                  }
        # Operation 3
        query3 = {"id": 3,
                  "method": "transact",
                  "params": [
                      "Open_vSwitch", {
                          "op": "update",
                          "table": "Nuage_Port_Table",
                          "where": [["name", "==", device_name]],
                          "row": {
                              "mac": mac_address,
                              "bridge": bridge,
                              "vm_domain": 5
                          }
                      }, {
                          "op": "update",
                          "table": "Nuage_VM_Table",
                          "where": [["vm_uuid", "==", port_id]],
                          "row": {
                              "state": 1,
                              "reason": 1,
                              "domain": 5,
                              "vm_name": port_id,
                              "ports": ["set", [device_name]]
                          }
                      }
                  ]
                  }
        # stitch the queries into one single query
        query.append(json.dumps(query1))
        query.append(json.dumps(query2))
        query.append(json.dumps(query3))

        # send the query one by one
        for q in query:
            cls.ovsdb_transaction(q)
        print("echo NuageVMDriver plug: sent the query \n")

    @classmethod
    def unplug(cls, port_id, device_name):
        print("echo Nuage unplugging port %(id)s:%(name)s on bridge \n",
              {'id': port_id,
               'name': device_name})

        # Formulate json object
        query = {"id": 1,
                 "method": "transact",
                 "params": [
                     "Open_vSwitch", {
                         "op": "mutate",
                         "table": "Nuage_VM_Table",
                         "where": [["vm_uuid", "==", port_id]],
                         "mutations": [["ports", "delete", device_name]]
                     }, {
                         "op": "delete",
                         "table": "Nuage_Port_Table",
                         "where": [["name", "==", device_name]]
                     }, {
                         "op": "delete",
                         "table": "Nuage_VM_Table",
                         "where": [["vm_uuid", "==", port_id]]
                     }
                 ]
                 }
        # send the obj
        cls.ovsdb_transaction(json.dumps(query))
        print("echo NuageVMDriver unplug: sent the query \n")

    @classmethod
    def get_port_uuid(cls, device_name):
        print("echo device name is : %s \n", device_name)
        port_id = None
        # Formulate json object
        query = {"id": 1,
                 "method": "transact",
                 "params": [
                     "Open_vSwitch", {
                         "op": "select",
                         "table": "Nuage_VM_Table",
                         "where": [["ports", "==", device_name]]
                     }
                 ]
                 }
        # send the obj
        response = cls.ovsdb_transaction(json.dumps(query), True)
        if response is not None \
                and response.get('result') is not None:
            port_id = response['result'][0]['rows'][0]['vm_uuid']
        return port_id


class NuageInterfaceDriver(OVSInterfaceDriver):
    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None, prefix=None, mtu=None):

        super(NuageInterfaceDriver, self).plug(
            network_id=network_id, port_id=port_id,
            device_name=device_name, mac_address=mac_address,
            bridge=bridge, namespace=namespace, prefix=prefix)

        if not bridge:
            bridge = self.conf.ovs_integration_bridge
            print("echo bridge is picked from conf bridge : %s \n", bridge)
        # Plug port into nuage overlay, simulate VM power on event
        print("echo Nuage plugging port %(id)s:%(name)s on bridge %(bridge)s"
              "in namespace %(namespace)s \n",
              {'id': port_id,
               'name': device_name,
               'bridge': bridge,
               'namespace': namespace})

        NuageVMDriver.plug(port_id=port_id, device_name=device_name,
                           mac_address=mac_address, bridge=bridge)

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        port_id = NuageVMDriver.get_port_uuid(device_name=device_name)
        if port_id is not None:
            print("echo Nuage unplugging port %(id)s: %(name)s \n",
                  {'id': port_id,
                   'name': device_name})

            NuageVMDriver.unplug(port_id=port_id, device_name=device_name)

        super(NuageInterfaceDriver, self).unplug(
            device_name=device_name, bridge=bridge,
            namespace=namespace, prefix=prefix)


def main():
    parser = parse_arguments()
    args = parser.parse_args()
    if args.unplug:
        try:
            print("echo unplugging\n")
            driver = NuageVMDriver
            driver.unplug(args.port_id, "o-hm0")
            print("echo Unplugging succesfull!")
        except Exception as e:
            print("echo Unplugging Octavia Management Port failed:\n%msg\n",
                  {'msg': str(e)})
    else:
        try:
            print("echo plugging\n")
            driver = NuageVMDriver
            driver.plug(args.port_id, "o-hm0", args.mac, "alubr0")
            print("echo Plugging Octavia Management Port succeeded\n")
        except Exception as e:
            print("echo Plugging Octavia Management Port failed:\n%msg\n",
                  {'msg': str(e)})


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mac",
                        required=False,
                        help="Mac Address of the Octavia management port")
    parser.add_argument("--port_id",
                        required=False,
                        help="Neutron ID of the Octavia Management port")
    parser.add_argument("--unplug",
                        required=False,
                        help="Unplug the Octavia Management Port")
    return parser


if __name__ == '__main__':
    main()
