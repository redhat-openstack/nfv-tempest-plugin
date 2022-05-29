#!/usr/bin/env python3

"""
Copyright 2022 Vadim Khitrin <me@vkhitrin.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
"""

# TODO(vkhitrin): enhance this very simple and silly script
#                 Add real async implementation.

import argparse
import logging
import time

from scapy.all import IP, TCP, UDP, Raw, send, sr, AsyncSniffer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def parse_args():
    parser = \
        argparse.ArgumentParser(description='scapy bidirectional UDP traffic')
    parser.add_argument('-s', '--sniff', required=True,
                        help='interface to sniff')
    parser.add_argument('-d', '--dest', required=True,
                        help='destination IP address of packet')
    parser.add_argument('-p', '--port', required=True,
                        help='source/dest port (identical)')
    parser.add_argument('-P', '--packets', default=100,
                        help='amount of packets to send')
    parser.add_argument('-u', '--udp', action="store_true",
                        help='use UDP instead of TCP')
    return parser.parse_args()


def construct_packet(dest_ip, port, udp):
    proto = TCP
    if udp:
        proto = UDP
    return IP(dst=dest_ip)/proto(dport=int(port),
                                 sport=int(port))/Raw(load="packet")


def async_sniffer(interface, port, packet_amount):
    """Requires scapy 2.4.3+

    Starts a sniffer async.
    """
    return AsyncSniffer(iface=interface, filter=f"port {port}",
                        count=packet_amount, store=True,
                        prn=lambda x: x.summary(),
                        timeout=300)


def send_packets(packet, packet_amount):
    send(packet, count=packet_amount)


def main():
    args = parse_args()
    packet = construct_packet(args.dest, args.port, args.udp)
    logger.info(f"Constructing packet: {packet}")
    sniffer = async_sniffer(args.sniff, args.port, args.packets)
    logger.info("Starting sniffer")
    sniffer.start()
    time.sleep(3)
    logger.info("Sniffer started, sleeping before sending traffic")
    logger.info(f"Sending {args.packets} packets")
    send_packets(packet, args.packets)
    # Run until X packets are received
    sniffer.join()


if __name__ == '__main__':
    main()
