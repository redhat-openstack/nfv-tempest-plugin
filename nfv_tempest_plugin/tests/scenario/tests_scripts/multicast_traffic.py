# Copyright 2017 Red Hat, Inc.
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

# The script sends/receives multicast traffic between multiple hosts.
# For the receivers, the following arguments should be passed:
# receive - Tells the host that it should receive the multicast traffic.
# group - The multicast address, hosts should bind to. Ex. '224.0.0.1'
# port - The port that hosts should wort with. Ex. 10000
#
# For the sender, the following arguments should be passed:
# send = Tells the host that it should send the multicast traffic.
# group - The multicast address, hosts should bind to. Ex. '224.0.0.1'
# port - The port that hosts should wort with. Ex. 10000
# message - Multicast message to pass to receive hosts.

import argparse
import socket
import struct

parser = argparse.ArgumentParser(
    description='This is multicast send/receive script.')
parser.add_argument('-r', '--receive', help='Receive the multicast traffic',
                    action='store_true', required=False)
parser.add_argument('-s', '--send', help='Send the multicast traffic',
                    action='store_true', required=False)
parser.add_argument('-g', '--group', help='Multicast bind group',
                    required=True)
parser.add_argument('-p', '--port', help='Multicast port', required=True)
parser.add_argument('-m', '--message', help='Multicast message',
                    required=False)
args = parser.parse_args()

if args.receive:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((args.group, int(args.port)))
    mreq = struct.pack("4sl", socket.inet_aton(args.group), socket.INADDR_ANY)

    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    while True:
        print(sock.recv(1024))
        break

if args.send:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    sock.sendto(args.message, (args.group, int(args.port)))
