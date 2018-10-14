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

# The script attempts to configure external network connectivity for instance
# Suited for guest instances with cloud-init accessing nova metadata server
# Uses device role tagging in order to configure NIC assigned to external
# custom_net_config.py script.
# The following arguments should be passed:
# tag - Tag that is assigned to port connected to external network,
#       Example = "myTag", Default = "external"

import argparse
import json
import logging
import os
import textwrap

parser = argparse.ArgumentParser(
    description='This is guest network configuration script')
parser.add_argument('-t', '--tag', help='External tag assigned to port',
                    required=True, default="external")
args = parser.parse_args()

logging.basicConfig(filename='/var/log/messages', filemode='a',
                    format='%(asctime)s %(name)s %(levelname)s: %(message)s',
                    datefmt="%h %d %H:%M:%S", level=logging.INFO)
logger = logging.getLogger("CustomNetConfig")

external_nic = None
external_mac = None

try:
    os.system("mount /dev/sr0 /mnt")
    logger.info("Mounted config drive")
    data = json.loads(open("/mnt/openstack/latest/meta_data.json").read())
    data = data["devices"]
    for dev in data:
        if "tags" in dev:
            tags = dev["tags"]
            for tag in tags:
                if args.tag == tag:
                    external_mac = dev["mac"]
                    logger.info("Found required tag:{0} for NIC:{1}"
                                .format(args.tag, external_mac))
    nics = os.listdir('/sys/class/net/')
    for nic in nics:
        path = "/sys/class/net/{0}/address".format(nic)
        mac_address = open(path).read().rstrip()
        if mac_address == external_mac:
            external_nic = nic
            logger.info("MAC address {0} is currently assigned to NIC: {1}"
                        .format(external_mac, external_nic))
    if external_nic is not None:
        logger.info("Will attempt to configure {0}".format(external_mac))
        os.system("rm -f /etc/sysconfig/network-scripts/ifcfg-eth*")
        nic_skeleton = '''
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
                       '''.format(external_nic, external_mac)
        nic_skeleton_clean = (textwrap.dedent(nic_skeleton)
                              .lstrip().encode('utf8'))
        open("/etc/sysconfig/network-scripts/ifcfg-{0}".format(external_nic),
             "w").write(nic_skeleton_clean)
        open("/etc/ssh/sshd_config", "a").write("\nUseDNS=no")
        os.system("systemctl restart network")
        os.system("systemctl restart sshd")
        logger.info("Done configuring network")
    else:
        logger.info("Missing tag:{0}".format(args.tag))
    os.system("umount /mnt")
    logger.info("Unmounted config drive")
except Exception:
    logger.info("Failed to perform script, abortting...")
