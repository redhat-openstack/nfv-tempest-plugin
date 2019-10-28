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

# The script attempts to generate ICMP and MPLS traffic as well as sniffing
# the traffic on defined interfaces.

import argparse
import logging
import sys
import time

from scapy.contrib.mpls import MPLS
from scapy.layers.inet import ICMP
from scapy.layers.inet import IP
from scapy.layers.l2 import Dot1Q
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.sendrecv import sendp
from scapy.sendrecv import sniff


parser = argparse.ArgumentParser(
    description='This is scapy send/receive traffic script.')
group = parser.add_mutually_exclusive_group()
group.add_argument('--icmp', help='Send/receive ICMP traffic', required=False,
                   action='store_true')
group.add_argument('--mpls', help='Send/receive MPLS traffic', required=False,
                   action='store_true')
group.add_argument('--sniff', help='Sniff incomming traffic',
                   action='store_true', required=False)
parser.add_argument('-i', '--interface', help='Use specified interface',
                    required=True)
parser.add_argument('-c', '--count', help='Number of packets to send/receive',
                    default=5, type=int)
parser.add_argument('-t', '--timeout', help='Timeout for the sniffing wait',
                    default=120, type=int)
parser.add_argument('--src-mac', help='Source mac address', required=False)
parser.add_argument('--dst-mac', help='Destination mac address',
                    required=False)
parser.add_argument('--src-ip', help='Source ip address', required=False)
parser.add_argument('--dst-ip', help='Destination ip address', required=False)
parser.add_argument('--iface-vlan', help='The vlan that will be set on the '
                                         'virtual interface',
                    type=int, required=False)
parser.add_argument('--test-vlan', help='The vlan that will be used for '
                                        'packets send',
                    type=int, required=False)
parser.add_argument('--raw-msg', help='Include raw massage into the packet',
                    required=False)
parser.add_argument('--keep-sniff', help='Keep sniffing for the packets and'
                                         'do not exit',
                    required=False, action='store_true')
args = parser.parse_args()

logging.basicConfig(filename='/tmp/scapy_traffic.log', filemode='a',
                    format='%(asctime)s %(name)s %(levelname)s: %(message)s',
                    datefmt="%h %d %H:%M:%S", level=logging.INFO)
handler = logging.StreamHandler(sys.stdout)
logger = logging.getLogger("ScapyTraffic")
logger.addHandler(handler)


class ScapyTraffic(object):

    def __init__(self):
        self.icmp = args.icmp
        self.mpls = args.mpls
        self.sniff = args.sniff
        self.iface = args.interface
        self.count = args.count
        self.timeout = args.timeout
        self.src_mac = args.src_mac
        self.dst_mac = args.dst_mac
        self.src_ip = args.src_ip
        self.dst_ip = args.dst_ip
        self.iface_vlan = args.iface_vlan
        self.test_vlan = args.test_vlan
        self.raw_msg = args.raw_msg

    def sniff_catch(self):
        return sniff(iface=self.iface, count=self.count, timeout=self.timeout)

    @staticmethod
    def sniff_parse(sniff_output=None):
        if sniff_output is not None:
            pkt_count = len(sniff_output)
            if 'MPLS' in sniff_output[0] and sniff_output[0].type == 34887:
                pkt_type = 'mpls'
            elif 'ICMP' in sniff_output[0] and \
                    sniff_output[0].getlayer(ICMP).type == 8:
                pkt_type = 'icmp'
            else:
                pkt_type = 'unidentified'
            custom_string = sniff_output[0].load if sniff_output[0].load \
                else False
            return {'pkt_count': pkt_count, 'pkt_type': pkt_type,
                    'custom_string': custom_string}
        return False

    def send_icmp(self):
        icmp_eth = Ether(src=self.src_mac, dst=self.dst_mac)
        icmp_id = Dot1Q(vlan=self.iface_vlan, id=3, prio=2) / Dot1Q(
            vlan=self.test_vlan, id=3, prio=2)
        icmp_ip = IP(src=self.src_ip, dst=self.dst_ip)
        icmp_icmp = ICMP()
        icmp_frame = icmp_eth / icmp_id / icmp_ip / icmp_icmp

        send_icmp_log = icmp_frame.sprintf("Packets send from mac: "
                                           "%Ether.src%, ip: %IP.src% to mac: "
                                           "%Ether.dst%, ip: %IP.dst% using "
                                           "vlans %Dot1Q.vlan% and")
        try:
            logger.info("Send ICMP traffic from the {iface} interface with "
                        "the following details: \n{packet_details} "
                        "{second_vlan}".format(iface=self.iface,
                                               packet_details=send_icmp_log,
                                               second_vlan=self.test_vlan))
            sendp(icmp_frame, iface=self.iface, count=self.count)
        except Exception as e:
            logger.info("The ICMP traffic send failed due"
                        " to: {}".format(e.message))
        return

    def send_mpls(self):
        mpls_eth = Ether(src=self.src_mac, dst=self.dst_mac, type=0x8847)
        mpls_lables = MPLS(label=16, s=0, ttl=255) / MPLS(
            label=18, s=0, ttl=255) / MPLS(
            label=18, s=0, ttl=255) / MPLS(
            label=16, s=1, ttl=255)
        mpls_ip = IP(src=self.src_ip, dst=self.dst_ip)
        mpls_icmp = ICMP(type="echo-request")
        mpls_raw = Raw(load=self.raw_msg)
        mpls_frame = mpls_eth / mpls_lables / mpls_ip / mpls_icmp / mpls_raw

        send_mpls_log = mpls_frame.sprintf("Packets send from mac: "
                                           "%Ether.src%, ip: %IP.src% to mac: "
                                           "%Ether.dst%, ip: %IP.dst% with the"
                                           " following raw message: "
                                           "%Raw.load%")
        try:
            logger.info("Send MPLS traffic from the {iface} interface with "
                        "the following details: \n{packet_details}"
                        .format(iface=self.iface,
                                packet_details=send_mpls_log))
            sendp(mpls_frame, iface=self.iface, count=self.count)
        except Exception as e:
            logger.info("The MPLS traffic send failed due"
                        " to: {}".format(e.message))
        return


def main():
    scap = ScapyTraffic()
    logger.info("Start scapy traffic script")

    if scap.sniff:
        timeout_start = time.time()
        while time.time() < timeout_start + args.timeout:
            logger.info("Start sniff on the {} "
                        "interface".format(args.interface))
            sniff_output = scap.sniff_catch()
            sniff_parse_out = None
            if sniff_output:
                sniff_parse_out = scap.sniff_parse(sniff_output)
                logger.info("Sniff parsed output: {}".format(sniff_parse_out))
            else:
                logger.error("The sniffer was unable to sniff any packet")
            if not args.keep_sniff and sniff_parse_out:
                return sniff_parse_out

    if scap.icmp:
        return scap.send_icmp()

    if scap.mpls:
        return scap.send_mpls()


if __name__ == '__main__':
    main()
