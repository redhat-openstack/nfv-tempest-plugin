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
import json
import paramiko
import re
import shlex
import subprocess as sp

from backports.configparser import ConfigParser
from collections import OrderedDict
from oslo_log import log
from oslo_serialization import jsonutils
from tempest import config
"""Python 2 and 3 support"""
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


def get_interfaces_from_overcloud_node(node_ip, cmd=None):
    """Retrieve interfaces from overcloud node

    :param node_ip:
    :param cmd:
    list member and return an array

    :return output:
    """
    if not cmd:
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
                              check_section, check_value,
                              multi_key_values=False):
    """Get value from INI configuration file

    :param overcloud_node:   The node that config should be pulled from
    :param config_path:      The path of the configuration file
    :param check_section:    Section within the config
    :param check_value:      Value that should be checked within the config
                             The variable could hold multiple values separated
                             by comma.
    :param multi_key_values: Flag on request to hold multiple values for
                             single key from ini file
    :return return_value
    """

    class M(OrderedDict):
        def __setitem__(self, key, value):
            v_val = self.get(key)
            if v_val is not None and type(value) == list:
                v_val.append(value[0])
            else:
                v_val = value
            # still using python2.7 super, for backport portability
            super(M, self).__setitem__(key, v_val)

    ini_config = get_overcloud_config(overcloud_node, config_path)
    config_parser_args = {'allow_no_value': True}
    if multi_key_values:
        config_parser_args['dict_type'] = M
    config_parser_args['strict'] = False
    get_value = ConfigParser(**config_parser_args)
    get_value.read_file(StringIO(ini_config))
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


def run_hypervisor_command_build_from_config(file_path, search_param,
                                             servers_ips,
                                             multi_key_values,
                                             command, filter_regexp=None):
    """buildandrun_hypervisor_command_from_config

    The method checks for a value [search_param] in controller/compute
    ini_file [file_path], build cli [command] include ini_param and run,
     on specific compute,
    the results are [filter_regexp] and returned as dict

    filtered by desired regexp [nic_req_status] res_dict returned for test.

    :param file_path:        Configuration ini file path
    :param search_param:     Search section-value in ini file
    :param servers_ips:      Host ip addresses hosting files and devices
    :param filter_regexp:    Regular expresion to search on filtered_command
    :param multi_key_values: Flag on request to hold multiple values for
                             single key
    :param command:          hypervisor command to be run regexp on
    :return res_dict
    """
    res_dict = {}
    for hypervisor in servers_ips:
        if hypervisor not in res_dict:
            res_dict[hypervisor] = []
        result = get_value_from_ini_config(hypervisor,
                                           file_path,
                                           search_param['section'],
                                           search_param['value'],
                                           multi_key_values)
        msg = "No {} found in".format(search_param)
        assert result != '', "{} {}".format(msg, hypervisor)

        result = "[" + result.replace('\n', ", ") + "]"
        dev_names = [x.get('devname') for x in json.loads(result)]
        # The nic-partitioning deployment does not store "devname" param.
        # It has the "domain", "function" and other attributes.
        # As a result, many None params added to the list.
        # The below command excludes the "None" from the list.
        dev_names = [devname for devname in dev_names if devname]
        cmd = ''
        for device in dev_names:
            cmd += "{} {};".format(command, device)
        result = \
            get_interfaces_from_overcloud_node(hypervisor, cmd)

        for line in result.split("\n"):
            nic_stat = line if not filter_regexp else re.\
                findall(filter_regexp, line)
            if len(nic_stat) > 0:
                res_dict[hypervisor].append(nic_stat[0])

    return res_dict


def find_vm_interface(ports=[],
                      vnic_type='normal'):
    """find vm interface

    The function receive port list and search for requested
    vnic_type.

    :param ports: ports connected to specific server
    :param vnic_type: vnic_type nomal/direct/direct_physical

    return port_id, ip_address
    """
    assert len(ports), 'ports is empty or None'
    return [[port['id'], port['fixed_ips'][0]['ip_address']]
            for port in ports['ports']
            if port['binding:vnic_type'] == vnic_type][0]


def continuous_ping(ip_dest,
                    mtu=1422,
                    duration=10):
    """continuous_ping

    The function send ping command in background mode
    from tempest host to fip vm

    :param ip_dest: comma separated ip dests
    :param mtu: ping mtu size to check
    :param duration: duration of ping test.
    """
    cmd = "nohup ping -i 1 -c {duration} -q " \
          "-s {mtu} {ip_dest}"
    msg = "no ping dest '{h}' "
    assert ip_dest, msg.format(h=ip_dest)
    ip_list = ip_dest.split(",")
    for ping_ip in ip_list:
        cmd_line = cmd.format(mtu=mtu, duration=duration, ip_dest=ping_ip)
        log_file = "/tmp/ping-{ip_dest}.txt".format(ip_dest=ping_ip)
        with open(log_file, 'w') as out:
            sp.Popen(shlex.split(cmd_line), stdout=out,
                     stderr=out)
        LOG.debug('pinging %(ping_ip)s for %(duration)s ')


def stop_continuous_ping():
    """stop continuous_ping

    The function does pgrep ping on local machines, send kill with
    stop statistics
    kill -SIGINT `pgrep ping
    """
    cmd = "pgrep ping"
    remote_command = shlex.split(cmd)
    pipe = sp.Popen(remote_command, stdout=sp.PIPE)
    ping_pid = pipe.stdout.read().decode('UTF-8')\
        .rstrip('\n').replace('\n', ' ')
    LOG.info("Found the following pids: {}".format(ping_pid))
    if ping_pid != '':
        cmd = "/bin/kill -SIGINT {}".format(ping_pid)
        remote_command = shlex.split(cmd)
        pipe = sp.Popen(remote_command, stdout=sp.PIPE)
        LOG.info("Ping process termiated {}".
                 format(pipe.stdout.read().decode('UTF-8').rstrip('\n')))
