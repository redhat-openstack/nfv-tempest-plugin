# The script sends multicast traffic to another host that is running mcast_receive.py script.
# The following arguments should be passed:
# group - The multicast address, hosts should bind to. Ex. '224.1.1.1'
# port - The port that hosts should wort with. Ex. 10000
# message - Multicast message to pass to receive hosts.
import argparse
import socket

parser = argparse.ArgumentParser(
    description='This is multicast send script.')
parser.add_argument('-g', '--group', help='Multicast bind group', required=True)
parser.add_argument('-p', '--port', help='Multicast port', required=True)
parser.add_argument('-m', '--message', help='Multicast message', required=True)
args = parser.parse_args()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
sock.sendto(args.message, (args.group, int(args.port)))
