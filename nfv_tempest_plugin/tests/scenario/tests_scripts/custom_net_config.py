#!/bin/env python
# Copyright 2018 Red Hat, Inc.
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
#
# Works only on python2
# The script attempts to configure network connectivity for instance
# Suited for guest instances with cloud-init accessing nova metadata server
# Uses device role tagging in order to configure NIC assigned to external
# Also can apply manual NIC config passed by user


import argparse
import json
import logging
import os
import re
import subprocess
import textwrap

DHCP_NIC_SKELETON = '''
                    DEVICE={0}
                    HWADDR={1}
                    BOOTPROTO=dhcp
                    BOOTPROTOv6=dhcp
                    ONBOOT=yes
                    TYPE=Ethernet
                    USERCTL=yes
                    PEERDNS=yes
                    IPV6INIT=yes
                    PERSISTENT_DHCLIENT=1
                    '''

STATIC_NIC_SKELETION = '''
                       DEVICE={0}
                       HWADDR={1}
                       IPADDR={2}
                       NETMASK=255.255.255.0
                       BOOTPROTO=static
                       BOOTPROTOv6=static
                       ONBOOT=yes
                       TYPE=Ethernet
                       USERCTL=yes
                       PEERDNS=no
                       IPV6INIT=yes
                       '''


# Parse CLI arguments
def parse_args():
    parser = argparse.ArgumentParser(
        description='Custom guest network configuration script')
    parser.add_argument('--tag', help='External tag assigned to port',
                        default='external')
    parser.add_argument('--ssh-no-dns', action='store_true',
                        help='Set SSH daemon to not use DNS')
    parser.add_argument('--cd-rom', help='CD-ROM device on guest',
                        default='/dev/sr0')
    parser.add_argument('--nic', action='append', required=False,
                        help='NIC type:mac:ip mapping to configure')
    return parser.parse_args()


# Configure logger to log messages to /var/log/messages
def configure_logger():
    logging.basicConfig(filename='/var/log/messages', filemode='a',
                        format='%(asctime)s %(name)s %(levelname)s:'
                               '%(message)s',
                        datefmt="%h %d %H:%M:%S", level=logging.INFO)
    return logging.getLogger("CustomNetConfig")


def map_macadress_to_nic(nics, mac):
    for nic in nics:
        path = "/sys/class/net/{0}/address".format(nic)
        mac_address = open(path).read().rstrip()
        if mac_address == mac:
            return nic


def restart_network(nic, logger):
    try:
        subprocess.call(['systemctl', 'restart', 'network'])
    except OSError:
        logger.info('Failed to configure networking due to NIC {}'
                    .format(nic))
        raise


def main():
    args = parse_args()
    logger = configure_logger()
    config_drive = args.cd_rom
    required_tag = args.tag
    manual_nics = args.nic
    configure_logger()
    # Init variables
    data = {}
    unconfigued_nics = []
    unused_mac_addresess = []
    external_nic = None
    external_mac = None
    if args.ssh_no_dns:
        open("/etc/ssh/sshd_config", "a").write("\nUseDNS=no")
        subprocess.call(['systemctl', 'restart', 'sshd'])
        logger.info("Set SSH daemon to ignore DNS resolve")
    if os.path.exists(config_drive):
        subprocess.call(['mount', config_drive, '/mnt'])
        logger.info("Mounted config drive")
    else:
        logger.info("Config drive not present, abortting")
        raise OSError(2, 'No such file or directory', config_drive)
    try:
        data = json.loads(open("/mnt/openstack/latest/meta_data.json").read())
    except OSError:
        logger.info('Failed to locate meta_data.json from config drive, '
                    'abortting')
        raise
    # From now on, we're assuming meta_data.json is structured correctly
    data = data["devices"]
    for dev in data:
        unused_mac_addresess.append(dev["mac"])
        if "tags" in dev:
            tags = dev["tags"]
            for tag in tags:
                if required_tag == tag:
                    external_mac = dev["mac"]
                    logger.info("Found required tag:{0} for NIC:{1}"
                                .format(required_tag, external_mac))
    unconfigued_nics = os.listdir('/sys/class/net/')
    # Remove loopback device
    unconfigued_nics.remove('lo')
    external_nic = map_macadress_to_nic(unconfigued_nics, external_mac)
    logger.info("MAC address {0} is currently assigned to NIC: {1}"
                .format(external_mac, external_nic))
    if external_nic is not None:
        logger.info("Will attempt to configure {0}".format(external_mac))
        subprocess.call(['rm', '-rf',
                        '/etc/sysconfig/network-scripts/ifcfg-eth*'])
        nic_skeleton_clean = (textwrap.dedent(DHCP_NIC_SKELETON.format(
                                                                external_nic,
                                                                external_mac))
                              .lstrip().encode('utf8'))
        open("/etc/sysconfig/network-scripts/ifcfg-{0}".format(external_nic),
             "w").write(nic_skeleton_clean)
        unused_mac_addresess.remove(external_mac)
        unconfigued_nics.remove(external_nic)
        restart_network(external_nic, logger)
    else:
        logger.info("Missing tag:{0}".format(args.tag))
    if manual_nics:
        for nic in manual_nics:
            nic_name = None
            try:
                nic_type, nic_mac, nic_ip = nic.split(',')
            except ValueError as e:
                map_args_num = re.findall(r'\d+', e.message)
                # We revieved less than 3 values
                if map_args_num:
                    map_args_num = map_args_num[0]
                    raise ValueError('Needed 3 values to unpack, recieved {}'
                                     .format(map_args_num))
                # We recieved more than 3 values
                else:
                    raise ValueError('Too many values to unpack, need 3'
                                     .format(e))
            nic_type = str.lower(nic_type)
            # We only support types 'dhcp' and 'static'
            if nic_type not in ['dhcp', 'static']:
                raise ValueError('{} not supported, please use dhcp or static'
                                 .format(nic_type))
            for mac in unused_mac_addresess:
                if mac == nic_mac:
                    nic_name = map_macadress_to_nic(unconfigued_nics, mac)
                    logger.info("Found manual nic mapping {0} is {1}"
                                .format(nic_mac, nic_name))
            if nic_name:
                if nic_type == 'dhcp':
                    nic_skeleton_clean = (textwrap.dedent(DHCP_NIC_SKELETON
                                                          .format(nic_name,
                                                                  nic_mac,
                                                                  nic_ip))
                                          .lstrip().encode('utf8'))
                    open("/etc/sysconfig/network-scripts/ifcfg-{0}"
                         .format(nic_name),
                         "w").write(nic_skeleton_clean)
                    unused_mac_addresess.remove(nic_mac)
                    unconfigued_nics.remove(nic_name)
                elif nic_type == 'static':
                    nic_skeleton_clean = (textwrap.dedent(STATIC_NIC_SKELETION
                                          .format(nic_name, nic_mac, nic_ip))
                                          .lstrip().encode('utf8'))
                    open("/etc/sysconfig/network-scripts/ifcfg-{0}"
                         .format(nic_name),
                         "w").write(nic_skeleton_clean)
                    unused_mac_addresess.remove(nic_mac)
                    unconfigued_nics.remove(nic_name)
            restart_network(nic_name, restart_network)

    if unconfigued_nics:
        logger.info("{} NICs are still unconfigured"
                    .format(len(unconfigued_nics)))
    logger.info("Done configuring network")
    subprocess.call(['umount', '/mnt'])
    logger.info("Unmounted config drive")


if __name__ == '__main__':
    main()

