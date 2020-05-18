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

import base64
import paramiko
import re
import subprocess as sp
import sys

from collections import namedtuple
from oslo_log import log
from oslo_serialization import jsonutils
from tempest import config
"""Python 2 and 3 support"""
from six.moves.configparser import ConfigParser
from six.moves import StringIO

CONF = config.CONF
LOG = log.getLogger('{} [-] nfv_plugin_test'.format(__name__))


def run_command_over_ssh(host, command):
    """This Method run Command Over SSH

    Provide Host, user and pass into configuration file

    :param host
    :param command
    """

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    """Assuming all check done in Setup,
    otherwise Assert failing the test
    """
    if CONF.nfv_plugin_options.overcloud_node_pkey_file_rsa:
        ssh.connect(host,
                    username=CONF.nfv_plugin_options.overcloud_node_user,
                    pkey=CONF.nfv_plugin_options.
                    overcloud_node_pkey_file_rsa)
    else:
        ssh.connect(host,
                    username=CONF.nfv_plugin_options.overcloud_node_user,
                    password=CONF.nfv_plugin_options.overcloud_node_pass)

    LOG.info("Executing command: %s" % command)
    stdin, stdout, stderr = ssh.exec_command(command)
    """
    In python3 the result returned is in bytes instead of literal
    We want to convert it to unicode
    """
    result = stdout.read().decode('UTF-8')
    ssh.close()
    return result


def get_interfaces_from_overcloud_node(node_ip):
    """Retrieve interfaces from overcloud node

    :param node_ip
    """
    cmd = 'sudo ip link show'
    output = run_command_over_ssh(node_ip, cmd)
    return output


def retrieve_content_from_files(node, files):
    """Retrieve encoded base64 content from files on Linux hosts

    Using a single SSH connection that executes a bash for loop that
    iterates over files to construct a JSON containing file's name and
    file's encoded content.

    The retrieved content will be decoded from base64.

    If file doesn't exist/can not be parsed, the content will be equal
    to 'None'.

    :param node: Which node to retrive content from
    :param files: List of files to retrive content from

    :return file_content
    """

    bash_list = ' '.join(files)
    file_content = {}
    # Create JSONs for each file with base64 encoded content
    # if file doesn't exist/can't be decodded returns 'None'
    cmd = '''
          function construct_json() {{
              echo "{{\\"$1\\": \\"$2\\"}}"
          }}

          a=({list})
          for file in ${{a[@]}}; do
              content="None"
              if [[ -f $file ]]; then
                      output=$(sudo base64 $file -w 0)
                      if [[ $output ]];then
                          content=$output
                     fi
              fi
              construct_json $file $content
          done
          '''.format(list=bash_list)

    guest_content = run_command_over_ssh(node, cmd).split('\n')
    # Output will always produce an additional unnecessary new line
    del guest_content[-1]
    # Parse and construct a JSON containing all the results
    for result in guest_content:
        file_content.update(jsonutils.loads(result))
    # Decode content from base64
    for content in file_content:
        if file_content[content] != 'None':
            parsed_content = base64.b64decode(file_content[content])
            file_content[content] = parsed_content.split('\n')

    return file_content


def retrieve_content_from_hiera(node, keys,
                                hiera_file='/etc/puppet/hiera.yaml'):
    """Get configuration values using hiera tool

    :param node: The node to retrieve the value from
    :param keys: The keys that should be provided to retrieve the value
                 Multiple keys should be provided as the array
    :param hiera_file: Hiera config file
    :return: List of the values returned
    """
    hiera_template = 'sudo hiera -c {hiera_file} {key};'
    hiera_command = ''
    for key in keys:
        hiera_command += hiera_template.format(hiera_file=hiera_file,
                                               key=key)
    hiera_content = run_command_over_ssh(node, hiera_command)
    hiera_content = hiera_content.replace(',\n', ',').strip().split('\n')
    return hiera_content


def parse_int_ranges_from_number_string(input_string):
    """Parses integers from number string

    :param input_string
    """
    # Assign helper variable
    parsed_input = []
    # Construct a list of integers from given number string,range
    for cell in input_string.split(','):
        if '-' in cell:
            start, end = cell.split('-')
            parsed_range = list(range(int(start), int(end) + 1))
            parsed_input.extend(parsed_range)
        else:
            parsed_input.append(int(cell))
    return parsed_input


def get_controllers_ip_from_undercloud(**kwargs):
    """This method returns the list of controllers ip

    :param kwargs['shell']
    """
    command = 'openstack server list -c \'Name\' -c ' \
              '\'Networks\' -f value | grep -i {0} | ' \
              'cut -d\"=\" -f2'.format('controller')
    ip_address_list = run_local_cmd_shell_with_venv(
        command, kwargs['shell'])
    return ip_address_list


def get_overcloud_config(overcloud_node, config_path):
    """Get overcloud configuration

    The method will get the config file by the provided path from the
    overcloud node specified by the user.
    The path could lead to the regular config path or to the
    containerized bind.

    :param overcloud_node: Which server to get config from
    :param config_path: The path of the configuration file

    :return config_data
    """

    get_config_data = 'sudo cat {0}'.format(config_path)
    config_data = run_command_over_ssh(overcloud_node,
                                       get_config_data)

    return config_data


def get_value_from_ini_config(overcloud_node, config_path,
                              check_section, check_value):
    """Get value from INI configuration file

    :param overcloud_node: The node that config should be pulled from
    :param config_path: The path of the configuration file
    :param check_section: Section within the config
    :param check_value: Value that should be checked within the config
                        The variable could hold multiple values separated
                        by comma.

    :return return_value
    """

    ini_config = get_overcloud_config(overcloud_node, config_path)
    # Python 2 and 3 support
    get_value = ConfigParser(allow_no_value=True)
    if sys.version_info[0] > 2:
        get_value = ConfigParser(allow_no_value=True, strict=False)
    get_value.readfp(StringIO(ini_config))
    value_data = []
    for value in check_value.split(','):
        value_data.append(get_value.get(check_section, value))

    return ','.join(value_data)


def run_local_cmd_shell_with_venv(command, shell_file_to_exec=None):
    """This Method runs command on tester local host

    Shell_file_to_exec path to source file default is None
    TBD: Add support to return, hosts list
    TBD: Return None in case no aggregation found.

    :param command
    :param shell_file_to_exec
    """
    if command == '':
        raise ValueError("command parameter is empty")
    if shell_file_to_exec is not None:
        source = 'source %s' % shell_file_to_exec
        pipe = sp.Popen(['/bin/bash', '-c', '%s && %s' % (
            source, command)], stdout=sp.PIPE)
    else:
        pipe = sp.Popen(['/bin/bash', '-c', '%s' % command],
                        stdout=sp.PIPE)
    """
    In python3 the result returned is in bytes instead of literal
    We want to convert it to unicode
    """
    result = pipe.stdout.read().decode('UTF-8')
    return result.split()


def check_pid_ovs(ip_address):
    """This method checks if ovs pid exist

    param ip_address: server ip address
    return  ovs pid or Exception if it does not exist
    """

    ovs_process = "sudo pidof ovs-vswitchd"
    ovs_process_pid = (run_command_over_ssh(ip_address,
                                            ovs_process))\
        .strip('\n')
    if not ovs_process_pid:
        raise ValueError('The ovs-vswitchd process is missing.')
    return ovs_process_pid


def check_guest_interface_config(ssh_client, provider_networks,
                                 hostname):
    """Check guest inteface network configuration

    The function aims to check if all provider networks are configured
    on guest operating system.

    :param ssh_client: SSH client configured to connect to server
    :param provider_networks: Server's provider networks details
    """
    for provider_network in provider_networks:
        mac = provider_network['mac_address']
        ip = provider_network['ip_address']
        # Attempt to discover guest interface using a MAC address
        guest_interface = ssh_client.get_nic_name_by_mac(mac)
        msg = ("Guest '{h}' has no interface with mac '{m}")
        assert guest_interface, msg.format(h=hostname,
                                           m=mac)
        LOG.info("Located '{m}' in guest '{h}' on interface '{g}'".format(
            m=mac, h=hostname, g=guest_interface))
        # Attempt to discover guest interface using an IP address
        ip_interface = ssh_client.get_nic_name_by_ip(ip)
        msg = ("Guest '{h}' exepected to have interface '{g}' to be "
               "configured with IP address '{i}'")
        assert ip_interface, msg.format(h=hostname, g=guest_interface,
                                        i=ip)
        LOG.info("Guest '{h}' has interface '{g}' configured with "
                 "IP address '{i}".format(h=hostname, g=guest_interface,
                                          i=ip))


def construct_ovs_bond_tuple_from_hypervsior(hypervisor, bond_object):
    """Queries hypervisor node and constructs a namedtuple object

    The namedtuple object stores information and commands associated to
    OVS bond.
    Currently only supports 'active-backup' bond.

    :param hypervisor: hypervisor IP address to fetch info from
    :param bond_obect: dictionary containing info regarding bond to query

    :returns ovs_bond: namedtuple of OVS bond query
    """
    bond = namedtuple('Bond', [
        'hypervisor',
        'interface',
        'type',
        'master_interface',
        'ovs_bridge',
        'networks',
        'ifup_cmd',
        'ifdown_cmd'
    ])
    check_bond_cmd = 'sudo ovs-appctl bond/show {}'
    bond_mode_re_filter = r'bond_mode:\s+.*'
    bond_mode_re_sub_filter = r'bond_mode:\s+(.*)'
    bond_interface = bond_object['interface']
    guest_networks = bond_object['guest_networks']
    # Query bond interface on hypervisor
    out = run_command_over_ssh(hypervisor,
                               check_bond_cmd.format(bond_interface))
    msg = ("Bond '{b}' not present on hypervisor '{h}'"
           .format(h=hypervisor, b=bond_interface))
    assert out != '', msg
    LOG.info("Bond '{b}' present on hypervisor '{h}'"
             .format(h=hypervisor, b=bond_interface))
    re_result = re.search(bond_mode_re_filter, out)
    msg = "Could not find bonding mode from bond query output"
    assert re_result is not None, msg
    re_bond_output = re_result.group(0)
    bond_mode = re.sub(bond_mode_re_sub_filter, r'\1',
                       re_bond_output)
    if bond_mode not in 'active-backup':
        raise ValueError('bond mode {} is not supported'
                         .format(bond_mode))
    LOG.info("Bond '{b}' is set to mode '{m}'"
             .format(b=bond_interface, m=bond_mode))
    re_result = re.search(r'active slave mac:\s+.*', out)
    re_bond_output = re_result.group(0)
    bond_master = re.sub(r'active slave mac:\s+.*\((.*)\)',
                         r'\1', re_bond_output)
    LOG.info("NIC '{m}' is set as master NIC in bond '{b}' on "
             "hypervisor '{h}'".format(m=bond_master,
                                       b=bond_interface,
                                       h=hypervisor))
    cmd = 'sudo ovs-vsctl port-to-br {}'
    # Fetch OVS general info
    ovs_bridge = run_command_over_ssh(hypervisor,
                                      cmd.format(bond_interface)).replace(
                                      '\n', '')
    # Construct interface up/down commands
    bond_if_up_cmd = 'sudo ovs-ofctl mod-port {b} {i} up'
    bond_if_down_cmd = 'sudo ovs-ofctl mod-port {b} {i} down'
    # Apply required variables for interface commands
    bond_if_up_cmd = bond_if_up_cmd.format(b=ovs_bridge,
                                           i=bond_master)
    bond_if_down_cmd = bond_if_down_cmd.format(b=ovs_bridge,
                                               i=bond_master)
    # Initialize a namedtuple of current bond
    ovs_bond = bond(hypervisor, bond_interface, bond_mode,
                    bond_master, ovs_bridge,
                    guest_networks, bond_if_up_cmd,
                    bond_if_down_cmd)
    return ovs_bond
