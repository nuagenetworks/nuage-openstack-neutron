# Copyright 2014 Alcatel-Lucent Canada Inc.
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

import errno
import os
import os.path
import re
import socket
import struct
import time

from neutron._i18n import _
from neutron.agent.linux.interface import OVSInterfaceDriver
from neutron.agent.linux import utils

import nuage_neutron.lbaas.common.exceptions as exceptions

from oslo_log import log as logging

LOG = logging.getLogger(__name__)


class NuageVMDriver(object):
    @classmethod
    def abs_file_name(cls, dir_, file_name):
        # If 'file_name' starts with '/', returns a copy of 'file_name'.
        # Otherwise, returns an absolute path to 'file_name' considering it
        # relative to 'dir_', which itself must be absolute.  'dir_' may be
        # None or the empty string, in which case the current working
        # directory is used.
        # Returns None if 'dir_' is None and getcwd() fails.
        # This differs from os.path.abspath() in that it will never change the
        # meaning of a file name.
        if file_name.startswith('/'):
            return file_name
        else:
            if dir_ is None or dir_ == "":
                try:
                    dir_ = os.getcwd()
                except OSError:
                    return None

            if dir_.endswith('/'):
                return dir_ + file_name
            else:
                return "%s/%s" % (dir_, file_name)

    @classmethod
    def get_connected_socket(cls):
        SOCKETNAME = "vm-events.ctl"
        OVSRUNDIR = "/var/run/openvswitch"
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_address = cls.abs_file_name(OVSRUNDIR, SOCKETNAME)
        try:
            sock.connect(server_address)
            LOG.debug(_("Connected to the vrs..."))
        except socket.error:
            raise exceptions.NuageDriverException(
                msg='Could not open a socket to VRS')

        return sock

    @classmethod
    def send_msg(cls, msg, sock, max_retries=5):
        ret = 0
        try:
            ret = sock.sendall(msg)
        except Exception:
            ''' Retry 5 times every second '''
            if (socket.errno in [errno.EBUSY, errno.EAGAIN]
                    and max_retries > 0):
                time.sleep(1)
                return cls.send_msg(msg, sock, max_retries=(max_retries - 1))
            else:
                raise
        return ret

    @classmethod
    def _send_vm_event_to_ovs(cls, nuage_uuid, eventStr, vm_name,
                              nuagexml=None):
        uuidstr = nuage_uuid.replace('-', '')
        part1 = int(uuidstr[:8], 16)
        part2 = int(uuidstr[8:16], 16)
        part3 = int(uuidstr[16:24], 16)
        part4 = int(uuidstr[24:32], 16)
        padchar = 0
        endpoint_type = 0
        platform_type = 0
        uuid_length = 128
        send_xml = None
        if (eventStr == 'DEFINED' or eventStr == 'STARTED' or eventStr ==
                'RESUMED'):
            send_xml = True
        else:
            send_xml = False
        eventtype = 0
        # Maps from vir-events.h
        eventStrMap = {'DEFINED': 0, 'UNDEFINED': 1, 'STARTED': 2,
                       'SUSPENDED': 3, 'RESUMED': 4, 'STOPPED': 5,
                       'SHUTDOWN': 6}
        stateStrMap = {'DEFINED': 0, 'UNDEFINED': 0, 'STARTED': 1,
                       'SUSPENDED': 3, 'RESUMED': 1, 'STOPPED': 4,
                       'SHUTDOWN': 5}
        reasonStrMap = {'DEFINED': 1,
                        'UNDEFINED': 0,
                        'STARTED': 1,
                        'SUSPENDED': 0,
                        'RESUMED': 1,
                        'STOPPED': 0,
                        'SHUTDOWN': 0}
        event = eventStrMap[eventStr]
        state = stateStrMap[eventStr]
        reason = reasonStrMap[eventStr]
        send_msg = None
        vm_name = vm_name.encode('utf-8')
        if send_xml:
            xml_len = len(str(nuagexml)) + 1
            send_msg = struct.pack('!BBHBBBBIIIIIIII64sHHHHHBBBBBB%ds' %
                                   xml_len, endpoint_type, platform_type,
                                   uuid_length, padchar, padchar, padchar,
                                   padchar, part1, part2, part3, part4,
                                   padchar, padchar, padchar, padchar,
                                   vm_name, event, eventtype, state, reason,
                                   xml_len, padchar, padchar, padchar,
                                   padchar, padchar, padchar, str(nuagexml))
        else:
            xml_len = 0
            send_msg = struct.pack('!BBHBBBBIIIIIIII64sHHHHHBBBBBB',
                                   endpoint_type, platform_type, uuid_length,
                                   padchar, padchar, padchar, padchar,
                                   part1, part2, part3, part4,
                                   padchar, padchar, padchar, padchar,
                                   vm_name, event, eventtype, state, reason,
                                   xml_len, padchar, padchar, padchar,
                                   padchar, padchar, padchar)
        return send_msg

    @classmethod
    def send_undefine(cls, vm_name, nuage_uuid, sock):
        stop_msg = cls._send_vm_event_to_ovs(nuage_uuid, 'STOPPED',
                                             vm_name)
        undefine_msg = cls._send_vm_event_to_ovs(nuage_uuid,
                                                 'UNDEFINED', vm_name)
        try:
            cls.send_msg(stop_msg, sock)
            cls.send_msg(undefine_msg, sock)
        except Exception as ex:
            raise exceptions.NuageDriverException(
                msg='Failed to send stop/undefine event to VRS :' + ex)

    @classmethod
    def nuage_xml(cls, nuage_uuid, local_mac, port, bridge):
        xmlTemplate = ("""<domain type="kvm" id="4">
               <name>%(name)s</name>
               <uuid>%(uuid)s</uuid>
               <metadata>
               </metadata>
               <devices>
               <interface type="bridge">
               <mac address="%(mac)s"></mac>
               <source bridge="%(bridge)s"></source>
               <target dev=\"%(port)s\"></target>
               </interface>
               </devices>
               </domain>""")
        data = {'name': nuage_uuid,
                'uuid': nuage_uuid,
                'mac': re.sub(r'\s+', '', local_mac),
                'bridge': bridge,
                'port': port}
        xmldata = xmlTemplate % data
        return xmldata

    @classmethod
    def plug(cls, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None, prefix=None, user_helper=None,
             mtu=None):
        xml_data = NuageVMDriver.nuage_xml(port_id, mac_address, device_name,
                                           bridge)
        define_msg = NuageVMDriver._send_vm_event_to_ovs(
            port_id, 'DEFINED', vm_name=port_id, nuagexml=xml_data)
        start_msg = NuageVMDriver._send_vm_event_to_ovs(
            port_id, 'STARTED', vm_name=port_id, nuagexml=xml_data)
        sock = cls.get_connected_socket()
        try:
            cls.send_msg(define_msg, sock)
            LOG.debug(_('Sent VM define event to VRS for UUID %s '),
                      port_id)
            cls.send_msg(start_msg, sock)
            LOG.debug(_('Sent VM start event to VRS for UUID %s '),
                      port_id)
        except Exception as ex:
            raise exceptions.NuageDriverError(
                msg='Failed to send define/start msg to VRS: ' + ex)

    @classmethod
    def unplug(cls, id, user_helper=None):
        sock = cls.get_connected_socket()
        cls.send_undefine(vm_name=id, nuage_uuid=id, sock=sock)


class NuageInterfaceDriver(OVSInterfaceDriver):
    def plug(self, network_id, port_id, device_name, mac_address,
             bridge=None, namespace=None, prefix=None):
        super(NuageInterfaceDriver, self).plug(network_id, port_id,
                                               device_name, mac_address,
                                               bridge, namespace, prefix)
        if not bridge:
            bridge = self.conf.ovs_integration_bridge
        # Plug port into nuage overlay, simulate VM power on event
        LOG.debug(_("Nuage plugging port %(id)s:%(name)s on bridge %(bridge)s "
                  "in namespace %(namespace)s"),
                  {'id': port_id,
                   'name': device_name,
                   'bridge': bridge,
                   'namespace': namespace})
        NuageVMDriver.plug(network_id, port_id, device_name,
                           mac_address, bridge, namespace, prefix,
                           user_helper=None)

    def unplug(self, device_name, bridge=None, namespace=None, prefix=None):
        cmd = ['ovs-appctl', 'vm/port-show']
        ports = utils.execute(cmd, run_as_root=True)

        # Search through the vports, find the one tied to the device_name
        for port in re.findall(r'Name: .*?\n\n\t\n', ports, re.DOTALL):
            port_conf = re.search(
                r'(?<=Name: )(?P<name>\S+).*(?<=UUID: )(?P<uuid>\S+).*'
                r'(?<=Name: )(?P<device_name>\S+).*'
                r'(?<=MAC: )(?P<mac_address>\S+).*'
                r'(?<=Bridge: )(?P<bridge>\S+)', port, re.DOTALL).groupdict()
            if port_conf is None:
                continue

            # If there is one matching the device name, delete it
            if port_conf.get('device_name') == device_name:
                LOG.debug(_('Nuage unplugging port %s'), port_conf)
                port_id = port_conf.get('name')
                NuageVMDriver.unplug(port_id, user_helper=None)
        super(NuageInterfaceDriver, self).unplug(device_name, bridge,
                                                 namespace, prefix)
