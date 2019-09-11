#!/bin/env python
# Copyright 2019 Red Hat, Inc.
# All Rights Reserved.
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

# The PostNetBootstrap script is aims to configure the post boot networking
# like virtual interface on the selected interface.

import argparse
import logging
import os
import subprocess
import sys

logging.basicConfig(filename='/var/log/messages', filemode='a',
                    format='%(asctime)s %(name)s %(levelname)s: %(message)s',
                    datefmt="%h %d %H:%M:%S", level=logging.INFO)
handler = logging.StreamHandler(sys.stdout)
logger = logging.getLogger("PostNetBootstrap")
logger.addHandler(handler)

parser = argparse.ArgumentParser(
    usage='''
    PostNetBootstrap test config script

    To add the VF based virtual interface and install scapy:
    $ python script.py --add-iface --port-type vf --mac aa:bb:cc:dd:ee:ff \
--vlan 10 --addr 10.10.10.10/24 --install-scapy

    To add the PF based virtual interface:
    $ python script.py --add-iface --port-type pf --mac aa:bb:cc:dd:ee:ff \
--vlan 10 --addr 10.10.10.12/24 --base-vlan 110

    To remove the VF based virtual interface:
    $ python script.py --del-iface --port-type vf --mac aa:bb:cc:dd:ee:ff \
--vlan 10

    To remove the PF based virtual interface:
    $ python script.py --del-iface --port-type pf --mac aa:bb:cc:dd:ee:ff
--base-vlan 110''')
iface = parser.add_mutually_exclusive_group()
iface.add_argument('--add-iface', help='Add virtual interface to server',
                   required=False, action='store_true')
iface.add_argument('--del-iface', help='Delete virtual interface from server',
                   required=False, action='store_true')
parser.add_argument('--port-type', help='The type of the virtual interface '
                                        'that should be created. VF or PF. '
                                        'The VF port, created as a regular '
                                        'virtual vlan interface. The PF port, '
                                        'is the direct passthrough to the '
                                        'instance, should be configured with '
                                        'the additional (base) vlan interface.'
                                        ' The test vlan will reside on top of'
                                        ' it',
                    choices=['vf', 'pf'], default='vf')
parser.add_argument('--mac', help='The mac address of the port that should '
                                  'be used for configuration')
parser.add_argument('--vlan', help='The vlan id that should be configured '
                                   'on the interface')
parser.add_argument('--addr', help='The address with the subnet that should '
                                   'be configured on the interface. '
                                   'Ex. 10.10.10.10/24')
parser.add_argument('--base-vlan', help='The vlan id that will be used as a '
                                        'based vlan for the PF. Look for type '
                                        'argument for the details.')
args = parser.parse_args()


def execute_shell_command(cmd):
    """Execute shell command

    The subprocess.check_output executes command provided as list.
    If the command will be provided as string, it will be converted to list
    and then executed.
    """
    if not isinstance(cmd, list):
        cmd = cmd.split()
    try:
        logger.info('Execute command: {}'.format(cmd))
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        logger.info('Command failed: {}'.format(e))
        raise
    return output


def check_existing_interfaces():
    """Check and locate existing network interfaces on instance"""
    ifaces = []
    nics = os.listdir('/sys/class/net/')
    nics.remove('lo')
    for nic in nics:
        nic_path = '/sys/class/net/{}/address'.format(nic)
        with open(nic_path, 'r') as f:
            mac = f.read().rstrip()
        ifaces.append({nic: mac})
    return ifaces


def choose_requested_interface(nics, mac):
    """The function will return an interface based on the mac provided"""
    for nic in nics:
        for nic_name, nic_mac in iter(nic.items()):
            if nic_mac == mac:
                return nic_name
    return None


def set_virtual_interface(port_type, nic, vlan, addr, base_vlan=None):
    """Create a vlan based virtual interface"""
    logger.info('Create a virtual interface for {} nic'.format(port_type))
    if port_type == 'pf' and base_vlan is not None:
        execute_shell_command('ip link add link {nic} name {nic}.{vlan} type '
                              'vlan id {vlan}'.format(nic=nic, vlan=base_vlan))
        logger.info('Bring the base virtual interface up')
        execute_shell_command('ip link set {nic}.{vlan} up'.format(
            nic=nic, vlan=base_vlan))
        nic = '{nic}.{vlan}'.format(nic=nic, vlan=base_vlan)

    execute_shell_command('ip link add link {nic} name {nic}.{vlan} type '
                          'vlan id {vlan}'.format(nic=nic, vlan=vlan))
    logger.info('Bring the virtual interface up')
    execute_shell_command('ip link set {nic}.{vlan} up'.format(
        nic=nic, vlan=vlan))
    logger.info('Set address {} on interface {}.{}'.format(addr, nic, vlan))
    execute_shell_command('ip addr add {addr} dev {nic}.{vlan}'.format(
        addr=addr, nic=nic, vlan=vlan))


def remove_virtual_interface(port_type, nic, vlan, base_vlan=None):
    """Delete a vlan based virtual interface"""
    logger.info('Delete virtual interface for {} nic'.format(port_type))
    if port_type == 'pf' and base_vlan is not None:
        vlan = base_vlan
    execute_shell_command('ip link del {nic}.{vlan}'.format(nic=nic,
                                                            vlan=vlan))


def main():
    logger.info('Start post net bootstrap script')
    ifaces = check_existing_interfaces()
    nic = choose_requested_interface(ifaces, args.mac)
    if args.add_iface:
        logger.info('Set and configure virtual interfaces')
        set_virtual_interface(args.port_type, nic, args.vlan, args.addr,
                              args.base_vlan)
    elif args.del_iface:
        remove_virtual_interface(args.port_type, nic, args.vlan,
                                 args.base_vlan)
    logger.info('Post net bootstrap script completed')


if __name__ == '__main__':
    main()
