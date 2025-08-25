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
import tempest.lib.exceptions
import time


from backports.configparser import ConfigParser
from collections import OrderedDict
from oslo_log import log
from oslo_serialization import jsonutils
from tempest import config
"""Python 2 and 3 support"""
from six.moves import StringIO

CONF = config.CONF
LOG = log.getLogger('{} [-] nfv_plugin_test'.format(__name__))


def run_command_over_ssh(host, command, paramiko_connect_opts={}):
    """This Method run Command Over SSH

    Provide Host, user and pass into configuration file

    :param host
    :param command
    :paramiko_connect_opts optional arguments for paramiko SSH client
    """

    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    if not paramiko_connect_opts:
        paramiko_connect_opts = {'allow_agent': False}

    """Assuming all check done in Setup,
    otherwise Assert failing the test
    """
    if CONF.nfv_plugin_options.overcloud_node_pkey_file_key_object:
        ssh.connect(host,
                    username=CONF.nfv_plugin_options.overcloud_node_user,
                    pkey=CONF.nfv_plugin_options.
                    overcloud_node_pkey_file_key_object,
                    **paramiko_connect_opts)
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
    cmd_nova = 'openstack server list -c \'Name\' -c ' \
               '\'Networks\' -f value | grep -i {0} | ' \
               'cut -d\"=\" -f2'.format('controller')
    cmd_metal = 'metalsmith -f value ' \
                '-c \'Node Name\' -c \'IP Addresses\' list ' \
                '| grep -i {0} | cut -d\"=\" -f2'.format('controller')

    command = """
    osp_version=$(sed -n 's/.* \\([0-9]\\+\\).*/\\1/p' /etc/rhosp-release)
    if [ \"$osp_version\" -ge \"17\" ]
    then
        {0}
    else
        {1}
    fi
    """.format(cmd_metal, cmd_nova)

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
            if v_val is not None and isinstance(value, list):
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
                                 hostname, ip_retries=3):
    """Check guest inteface network configuration

    The function aims to check if all provider networks are configured
    on guest operating system.

    :param ssh_client: SSH client configured to connect to server
    :param provider_networks: Server's provider networks details
    :param hostname: server host name
    :param ip_retries: number of ip retries
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
        # Attempt to discover guest interface using a MAC address
        # Added retries just in case ips are assigned by dhcp and it takes
        # some time
        for counter in range(ip_retries):
            ip_interface = ssh_client.get_nic_name_by_ip(ip)
            if ip_interface:
                break
            else:
                LOG.info("IP address not configured yet for Guest '{h}' "
                         "interface '{g}'".format(h=hostname,
                                                  g=guest_interface))
                time.sleep(5)
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


def find_vm_interface_network_id(ports=[],
                                 network_id=None):
    """find vm interface with network_id

    The function receive port list and search for requested
    network_id.

    :param ports: ports connected to specific server
    :param network_id: network_id

    return port_id, ip_address
    """
    assert len(ports), 'ports is empty or None'
    return [[port['id'], port['fixed_ips'][0]['ip_address']]
            for port in ports['ports']
            if port['network_id'] == network_id][0]


def continuous_ping(ip_dest,
                    mtu=1422,
                    duration=10,
                    ssh_client_local=None):
    """continuous_ping

    The function send ping command in background mode
    if ssh_client_local is not configured it will ping from tempest
    host, otherwise it will ping using ssh_client_local

    :param ip_dest: comma separated ip dests
    :param mtu: ping mtu size to check
    :param duration: duration of ping test.
    :param ssh_client_local: ssh client to them vm from which ping
           will be executed
    """
    cmd = "nohup ping -i 1 -c {duration} -q " \
          "-s {mtu} {ip_dest}"
    msg = "no ping dest '{h}' "
    assert ip_dest, msg.format(h=ip_dest)
    ip_list = ip_dest.split(",")
    for ping_ip in ip_list:
        cmd_line = cmd.format(mtu=mtu, duration=duration, ip_dest=ping_ip)
        log_file = "/tmp/ping-{ip_dest}.txt".format(ip_dest=ping_ip)
        if ssh_client_local:
            cmd_line += "> {} 2>&1 &".format(log_file)
            ssh_client_local.exec_command(cmd_line)
        else:
            with open(log_file, 'w') as out:
                sp.Popen(shlex.split(cmd_line), stdout=out,
                         stderr=out)
        LOG.debug('pinging %(ping_ip)s for %(duration)s ')


def stop_continuous_ping(ssh_client_local=None):
    """stop continuous_ping

    if ssh_client_local is not configured it will stop ping from tempest
    host, otherwise it will stop ping using ssh_client_local

    :param ssh_client_local: ssh client to them vm from which ping
           will be stopped
    """
    cmd = "if pgrep ping; then sudo pkill ping; fi"
    if ssh_client_local:
        ssh_client_local.exec_command(cmd)
    else:
        sp.Popen(shlex.split(cmd), stdout=sp.PIPE)
    LOG.info("Ping process terminated")


def get_vf_from_mac(mac, hypervisor_ip):
    """get VF from MAC

    :param mac: mac address to search
    :param hypervisor_ip: hypervisor in which the vf should be found

    :return vf: returns VF associated to the mac address,
                        None if not found
    """
    vf_number_cmd = "ip link | grep {} | awk '{{print $2}}'".format(mac)
    vf_nic_cmd = "ip link | grep -B 1000 {} | grep \"^[0-9]*:\" | " \
                 "tail -1 | awk -F ':' '{{print $2}}'".format(mac)
    vf_number = run_command_over_ssh(hypervisor_ip, vf_number_cmd).strip()
    vf_nic = run_command_over_ssh(hypervisor_ip, vf_nic_cmd).strip()

    vf_out = None
    if vf_number and vf_nic_cmd:
        vf_out = "{}_{}".format(vf_nic, vf_number)
    return vf_out


def iperf_server(binding_ip, binding_port, duration,
                 protocol, ssh_client_local, log_file=""):
    """execute iperf server

    The function executes iperf server in background mode

    :param binding_ip: ip the server will be listening
    :param binding_port: port the server will be listening
    :param duration: time the server will be up
    :param protocol: udp or tcp
    :param ssh_client_local: ssh client to them vm from which
           iperf will be executed
    :param log_file: log file to use
    :return log_file: iperf output
    """
    # Check if iperf binary is present in $PATH
    protocols = {"tcp": "", "udp": "-u"}
    if log_file == "":
        log_file = "/tmp/iperf_server-{}-{}-{}-{}.txt".format(binding_ip,
                                                              binding_port,
                                                              protocol,
                                                              duration)
    try:
        ssh_client_local.exec_command('which iperf')
        cmd_line = "nohup sh -c \"echo -e 'iperf -s -B {} " \
                   r"-p {} -t {} {} &\\necho pid:\$!' > iperf3s;" \
                   "chmod +x iperf3s;./iperf3s\" > {} 2>&1".\
            format(binding_ip, binding_port, duration,
                   protocols[protocol], log_file)
    except tempest.lib.exceptions.SSHExecCommandFailed:
        try:
            ssh_client_local.exec_command('which iperf3')
            cmd_line = "nohup sh -c \"echo -e 'timeout {} iperf3 -s -B {} " \
                       r"-p {} &\\necho pid:\$!' > iperf3s;" \
                       "chmod +x iperf3s;./iperf3s\" > {} 2>&1".\
                format(duration, binding_ip, binding_port, log_file)
        except tempest.lib.exceptions.SSHExecCommandFailed:
            raise ValueError("iperf/iperf3 binaries were not found in $PATH")

    LOG.debug('Started iperf server: {}'.format(cmd_line))
    ssh_client_local.exec_command(cmd_line)
    return log_file


def iperf_client(server_ip, server_port, duration,
                 protocol, ssh_client_local, log_file=""):
    """execute iperf server

    The function executes iperf client in background mode

    :param server_ip: ip the server will connect to
    :param server_port: port the server will connect to
    :param duration: time the client will be up
    :param protocol: udp or tcp
    :param ssh_client_local: ssh client to them vm from which
           iperf will be executed
    :param log_file: log file
    :return log_file: iperf output
    """
    protocols = {"tcp": "", "udp": "-u"}

    if log_file == "":
        log_file = "/tmp/iperf_client-{}-{}-{}-{}.txt".format(server_ip,
                                                              server_port,
                                                              protocol,
                                                              duration)
    try:
        ssh_client_local.exec_command('which iperf')
        iperf_binary = 'iperf'
    except tempest.lib.exceptions.SSHExecCommandFailed:
        try:
            ssh_client_local.exec_command('which iperf3')
            iperf_binary = 'iperf3'
        except tempest.lib.exceptions.SSHExecCommandFailed:
            raise ValueError("iperf/iperf3 binaries were not found in $PATH")

    cmd_line = "nohup sh -c \"echo -e '{} -c {} -T s2 -p {} -t {} {} " \
               r"&\\necho pid:\$!' > iperf3c; chmod +x iperf3c;" \
               "./iperf3c\" > {} 2>&1".\
        format(iperf_binary, server_ip, server_port, duration,
               protocols[protocol], log_file)

    LOG.debug('Started iperf client: {}'.format(cmd_line))
    ssh_client_local.exec_command(cmd_line)
    return log_file


def stop_iperf(ssh_client_local, iperf_file):
    """Stop iperf and return log file

    The function stops iperf if it is running and returns log file

    :param ssh_client_local: ssh client to them vm
    :param iperf_file: iperf file with its output
    :return iperf_output: content of iperf_file
    """
    # First line contains process pid
    stop_cmd = "(file={};pid=$(grep pid $file | awk -F: '{{print $2}}')" \
               ";sudo kill $pid||echo '';sudo head -10 $file;) 2>&1".\
        format(iperf_file)
    LOG.info('Stop iperf on vm: {}'.format(stop_cmd))
    out = ssh_client_local.exec_command(stop_cmd)
    LOG.info('iperf output: {}'.format(out))
    return out


def tcpdump(server_ip, interface, duration, macs=[], protocol=None, port=None,
            hosts=[]):
    """Execute tcpdump on hypervisor

    The function executes tcpdump on hypervisor in background mode

    :param server_ip: server in which tcpdump will be executed
    :param interface: interface in which tcpdump will be executed
    :param duration: duration in seconds of the capture
    :param macs: list of mac addresses
    :param protocol: protocol to capture: tcp, udp, icmp
    :param port: port to capture
    :param host: host ip addresses
    :return filename: text filename with the capture
    """
    file = "/tmp/dump_{}_{}_{}_{}_{}_{}.txt".format(
        interface, '' if protocol is None else protocol,
        duration, '' if port is None else str(port),
        '-'.join(hosts),
        '-'.join(macs))
    filters = [' ether host ' + mac for mac in macs]
    filters.append(protocol)
    filters.append('port ' + str(port) if port is not None else None)
    filters += [' host ' + host for host in hosts]
    filters_str = ' and '.join([filter for filter in filters if filter])
    tcpdump_cmd = "date +'%H:%M:%S.0 START_TIME' > {}; sudo nohup timeout " \
                  "{} tcpdump -i {} -nne {} >> {} 2>&1 &".format(file,
                                                                 duration,
                                                                 interface,
                                                                 filters_str,
                                                                 file)
    LOG.info('Executed tcpdump on {}: {}'.format(server_ip, tcpdump_cmd))
    run_command_over_ssh(server_ip, tcpdump_cmd)
    return file


def tcpdump_time_filter(dump, start_time=None, end_time=None):
    """Filter tcpdump output by timestamp

    Filter tcpdump output by timestamp
    Firstline of dump contains the timestamp at which tcpdump was executed
    14:04:12 START_TIME

    :param dump: tcpdump string to filter
    :param start: start time in seconds from the begining
    :param end: end time  in seconds from the begining
    :return tcpdump_filter: time filtered tcpdump
    """

    tcpdump_start_timestamp = None
    output = []
    for line in dump.split('\n'):
        columns = line.split(' ')
        flags = [True, True]
        if (len(columns) > 0):
            try:
                timestamp = time.strptime(columns[0].split('.')[0],
                                          '%H:%M:%S')
            except ValueError:
                continue
            if tcpdump_start_timestamp is None:
                tcpdump_start_timestamp = timestamp
                continue
            diff = (time.mktime(timestamp)
                    - time.mktime(tcpdump_start_timestamp))
            if start_time is not None and diff < start_time:
                flags[0] = False
            if end_time is not None and diff > end_time:
                flags[1] = False
            if flags[0] and flags[1]:
                output.append(line)

    return '\n'.join(output)


def stop_tcpdump(server_ip, tcpdump_file):
    """Stop tcpdump and return log file

    The function stops tcpdump if it is running and returns log file

    :param server_ip: server in which tcpdump is running
    :param tcpdump_file: tcpdump file with its output
    :return tcpdump_output: content of tcpdump_file
    """
    stop_cmd = '(if pgrep tcpdump; then sudo pkill tcpdump;' \
               ' fi; file={}; sudo cat $file | head -200; ' \
               'sudo rm $file) 2>&1'.format(tcpdump_file)
    LOG.info('Executed on {}: {}'.format(server_ip, stop_cmd))
    out = run_command_over_ssh(server_ip, stop_cmd)
    LOG.info('tcpdump output: {}'.format(out))
    return out


def get_offload_flows(server_ip):
    """Get offload flows from hypervisor

    The function stops tcpdump if it is running and returns log file

    :param server_ip: server in which tcpdump is running
    :param tcpdump_file: tcpdump file with its output
    :return tcpdump_output: content of tcpdump_file
    """
    cmd_flows = 'sudo ovs-appctl dpctl/dump-flows -m type=offloaded'
    LOG.info('Executed on {}: {}'.format(server_ip, cmd_flows))
    out = run_command_over_ssh(server_ip, cmd_flows)
    LOG.info('offload flows output: {}'.format(out))
    return out


def _get_cpu_details(node_ip):
    """Get CPU details from node

    :param node_ip IP address of node
    :return cpu_model CPU model
    :return cpu_flags CPU flags
    """
    cmd = "sudo lscpu | grep 'Model name';sudo lscpu | grep 'Flags'"
    output = run_command_over_ssh(node_ip, cmd)
    if output:
        cpu_model = ""
        cpu_flags = []
        params = output.split('\n')
        if params:
            for param in params:
                if "Model name" in param:
                    cpu_model = param.split(':')[1].strip(' \n')
                elif "Flags" in param:
                    cpu_flags = param.split(':')[1].strip(' \n').split(' ')
        return cpu_model, cpu_flags
    else:
        msg = "Unable to determine 'CPU Model name'"
        raise Exception(msg)


def get_cpu_iommu_kernel_arg(node_ip):
    """Get IOMMU kernel argument based on CPU

    :param node_ip IP address of node
    :return kernel_arg kernel arg
    """
    kernel_arg = None
    cpu_model, cpu_flags = _get_cpu_details(node_ip)
    if cpu_model.startswith('Intel'):
        kernel_arg = 'intel_iommu=on'
    elif cpu_model.startswith('AMD'):
        kernel_arg = 'amd_iommu=on'
    return kernel_arg


def get_conntrack_table(hypervisor_ip):
    """Get conntrack table from hypervisor

    Reads connection tracking table

    :param hypervisor_ip: IP of hypervisor
    :return conntrack_table: Connection tracking table
    """
    cmd_conn_track = 'sudo cat /proc/net/nf_conntrack'
    LOG.info('Executed on {}: {}'.format(hypervisor_ip, cmd_conn_track))
    out = run_command_over_ssh(hypervisor_ip, cmd_conn_track)
    LOG.info('{}. conntrack table: {}'.format(hypervisor_ip, out))
    return out


def get_nic_devname_from_address(node, pci_address):
    """Get the NIC devname from the PCI address

    Get the NIC devname from the PCI addres by traversing the
    /sys/class/pci_bus/*/device/{pci_address}/net directory and reading the
    uevent files.

    The uevent file has this format:
    [root@computehwoffload-0 ~]# cat /sys/class/pci_bus/*/device/0000:04:00.0/
    net/enp4s0f0/uevent
    INTERFACE=enp4s0f0
    IFINDEX=10

    In case we have more than one devname for the same PCI address the
    INTERFACE the one with the lowest IFINDEX is taken. In the example below
    we'll take enp4s0f0 as devname since it has the lowest IFINDEX:
    [root@computehwoffload-0 ~]#
    ls /sys/class/pci_bus/*/device/0000:04:00.0/net
    enp4s0f0  enp4s0f0_0  enp4s0f0_1  enp4s0f0_2  enp4s0f0_3  enp4s0f0_4
    enp4s0f0_5  enp4s0f0_6 enp4s0f0_7  enp4s0f0_8  enp4s0f0_9
    [root@computehwoffload-0 ~]#
    cat /sys/class/pci_bus/*/device/0000:04:00.0/net/enp4s0f0/uevent
    INTERFACE=enp4s0f0
    IFINDEX=10
    [root@computehwoffload-0 ~]#
    cat /sys/class/pci_bus/*/device/0000:04:00.0/net/enp4s0f0_0/uevent
    INTERFACE=enp4s0f0_0
    IFINDEX=26

    :param node The node IP address
    :param pci_address The NIC PCI address
    :return The NIC devname
    """

    pciaddr_to_devname_script = f"""
    ifindex="1000000"
    for uevent in \
    $(find /sys/class/pci_bus/*/device/{pci_address}/net -name uevent)
    do
        source "$uevent"
        if [ "$IFINDEX" -lt "$ifindex" ]
        then
            devname="$INTERFACE"
            ifindex="$IFINDEX"
        fi
    done
    echo "$devname"
    """
    output = run_command_over_ssh(node, pciaddr_to_devname_script).strip()

    return output


def get_open_vswitch_other_config(host, param_name):
    """This Method run sudo ovs-vsctl set

    sudo ovs-vsctl set . other_config:param_name=param_value

    Provide Host, param_name and it returns the param value

    :param host
    :param param_name
    """

    cmd = 'sudo ovs-vsctl --format=json get ' \
        'open_vswitch . other_config'

    # parse cmd command
    output = run_command_over_ssh(host, cmd)
    # missing double quotes in json, fixing it
    # {dpdk-extra=" -n 4", dpdk-init="true", dpdk-socket-mem="4096,1024",
    # pmd-auto-lb="true", pmd-auto-lb-improvement-threshold="50",
    # pmd-auto-lb-load-threshold="70", pmd-auto-lb-rebal-interval="3",
    # pmd-cpu-mask=fc}
    output = output.replace("=", "\":\"").replace("{", "{\"").\
        replace("}", "\"}").replace(", ", "\", \"").\
        replace("\"\"", "\"")

    value = json.loads(output)
    if (param_name in value.keys()):
        return value[param_name]


def set_open_vswitch_other_config(host, param_name, param_value):
    """This Method run sudo ovs-vsctl set open_vSwitch

    ovs-vsctl set open_vSwitch . other_config:param_name=param_value

    Provide Host, param_name and param_value into configuration file

    :param host
    :param param_name
    :param param_value
    """

    cmd = 'sudo ovs-vsctl --no-wait set open_vSwitch . ' \
        'other_config:{}={}'.format(param_name, param_value)

    LOG.info('set_open_vSwitch_other_config cmd {}'.format(cmd))

    # servers_dict['testpmd']['hypervisor_ip']
    result = run_command_over_ssh(
        host,
        cmd)

    return result
