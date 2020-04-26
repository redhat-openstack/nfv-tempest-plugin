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
import os.path
import paramiko
import re
import subprocess as sp
import sys
import textwrap
import time
import xml.etree.ElementTree as ELEMENTTree
import yaml

from oslo_log import log
from oslo_serialization import jsonutils
from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest.test import BaseTestCase
"""Python 2 and 3 support"""
from six.moves.configparser import ConfigParser
from six.moves import StringIO
from six.moves.urllib.parse import urlparse

CONF = config.CONF
LOG = log.getLogger('{} [-] nfv_plugin_test'.format(__name__))


def _run_command_over_ssh(host, command):
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
    output = _run_command_over_ssh(node_ip, cmd)
    return output


def _retrieve_content_from_files(node, files):
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

    guest_content = _run_command_over_ssh(node, cmd).split('\n')
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


def _retrieve_content_from_hiera(node, keys,
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
    hiera_content = _run_command_over_ssh(node, hiera_command)
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


def _get_controllers_ip_from_undercloud(**kwargs):
    """This method returns the list of controllers ip

    :param kwargs['shell']
    """
    command = 'openstack server list -c \'Name\' -c ' \
              '\'Networks\' -f value | grep -i {0} | ' \
              'cut -d\"=\" -f2'.format('controller')
    ip_address_list = _run_local_cmd_shell_with_venv(
        command, kwargs['shell'])
    return ip_address_list


def _get_overcloud_config(overcloud_node, config_path):
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
    config_data = _run_command_over_ssh(overcloud_node,
                                        get_config_data)

    return config_data


def _get_value_from_ini_config(overcloud_node, config_path,
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

    ini_config = _get_overcloud_config(overcloud_node, config_path)
    # Python 2 and 3 support
    get_value = ConfigParser(allow_no_value=True)
    if sys.version_info[0] > 2:
        get_value = ConfigParser(allow_no_value=True, strict=False)
    get_value.readfp(StringIO(ini_config))
    value_data = []
    for value in check_value.split(','):
        value_data.append(get_value.get(check_section, value))

    return ','.join(value_data)


def _run_local_cmd_shell_with_venv(command, shell_file_to_exec=None):
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


def _check_pid_ovs(ip_address):
    """This method checks if ovs pid exist

    param ip_address: server ip address
    return  ovs pid or Exception if it does not exist
    """

    ovs_process = "sudo pidof ovs-vswitchd"
    ovs_process_pid = (_run_command_over_ssh(ip_address,
                                             ovs_process)).strip('\n')
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
        BaseTestCase.assertNotEmpty(guest_interface,
                                    msg.format(h=hostname,
                                               m=mac))
        LOG.info("Located '{m}' in guest '{h}' on interface '{g}'".format(
            m=mac, h=hostname, g=guest_interface))
        # Attempt to discover guest interface using an IP address
        ip_interface = ssh_client.get_nic_name_by_ip(ip)
        msg = ("Guest '{h}' exepected to have interface '{g}' to be "
               "configured with IP address '{i}'")
        BaseTestCase.assertNotEmpty(ip_interface,
                                    msg.format(h=hostname,
                                               g=guest_interface,
                                               i=ip))
        LOG.info("Guest '{h}' has interface '{g}' configured with "
                 "IP address '{i}".format(h=hostname, g=guest_interface,
                                          i=ip))


class TestUtilsMixin(object):
    def read_external_config_file(self):
        """This Method reads network_config.yml

        Reads config data and assign it to dictionaries
        """
        with open(CONF.nfv_plugin_options.external_config_file, 'r') as f:
            self.external_config = yaml.safe_load(f)

        if not os.path.exists(
                CONF.nfv_plugin_options.external_resources_output_file):
            """Hold flavor, net and images lists"""
            # TODO(read and parse to util move to util)
            networks = self.networks_client.list_networks()['networks']
            flavors = self.flavors_client.list_flavors()['flavors']
            images = self.image_client.list_images()['images']

            if 'networks' in self.external_config:
                """
                Iterate over networks mandatory vars in external_config are:
                port_type, gateway_ip
                """
                for net in self.external_config['networks']:
                    self.test_network_dict[net['name']] = {'port_type': net[
                        'port_type'], 'gateway_ip': net['gateway_ip']}
                    """
                    Check for existence of optionals vars:
                    router_name, external.
                    """
                    if 'external' in net:
                        self.test_network_dict[net['name']]['external'] = net[
                            'external']
                    if 'router_name' in net:
                        self.test_network_dict[net['name']]['router'] = net[
                            'router_name']

                # iterate networks
                for net in iter(self.test_network_dict.keys()):
                    for network in networks:
                        if network['name'] == net:
                            self.test_network_dict[net]['net-id'] = \
                                network['id']

        # Insert here every new parameter.
        for test in self.external_config['tests-setup']:
            self.test_setup_dict[test['name']] = {}
            self.test_setup_dict[test['name']]['config_dict'] = {}
            if 'flavor' in test and test['flavor'] is not None:
                self.test_setup_dict[test['name']]['flavor'] = test['flavor']
            if 'package-names' in test and test['package-names'] is not None:
                self.test_setup_dict[test['name']]['package-names'] = \
                    test['package-names']
            if 'image' in test and test['image'] is not None:
                self.test_setup_dict[test['name']]['image'] = \
                    test['image']
            if 'router' in test and test['router'] is not None:
                self.test_setup_dict[test['name']]['router'] = \
                    test['router']
            if 'service-names' in test and test['service-names'] is not None:
                self.test_setup_dict[test['name']]['service-names'] = \
                    test['service-names']
            if 'tuned-profile' in test and test['tuned-profile'] is not None:
                self.test_setup_dict[test['name']]['tuned-profile'] = \
                    test['tuned-profile']
            if 'mtu' in test and test['mtu'] is not None:
                self.test_setup_dict[test['name']]['mtu'] = \
                    test['mtu']
            if 'emulatorpin_config' in test and test['emulatorpin_config'] \
                    is not None:
                for item in test['emulatorpin_config']:
                    for key, value in iter(item.items()):
                        if not value:
                            raise ValueError('The {0} configuration is '
                                             'required for the emulatorpin '
                                             'test, but currently empty.'
                                             .format(key))
                epin_str = jsonutils.dumps(test['emulatorpin_config'])
                self.test_setup_dict[test['name']]['config_dict'] = \
                    jsonutils.loads(epin_str)
            if 'rx_tx_config' in test and test['rx_tx_config'] is not None:
                for item in test['rx_tx_config']:
                    for key, value in iter(item.items()):
                        if not value:
                            raise ValueError('The {0} configuration is '
                                             'required for the tx/tx test, '
                                             'but currently empty.'
                                             .format(key))
                rx_tx_str = jsonutils.dumps(test['rx_tx_config'])
                self.test_setup_dict[test['name']]['config_dict'] = \
                    jsonutils.loads(rx_tx_str)
            if 'bonding_config' in test and test['bonding_config'] is not None:
                for item in test['bonding_config']:
                    for key, value in iter(item.items()):
                        if not value:
                            raise ValueError('The {0} configuration is '
                                             'required for the bondig '
                                             'test, but currently empty.'
                                             .format(key))
                bonding_str = jsonutils.dumps(test['bonding_config'])
                test_setup_dict = self.test_setup_dict[test['name']]
                test_setup_dict['config_dict']['bonding_config'] = \
                    jsonutils.loads(bonding_str)
            if 'igmp_config' in test and test['igmp_config'] is not None:
                for item in test['igmp_config']:
                    for key, value in iter(item.items()):
                        if not value:
                            raise ValueError('The {0} configuration is '
                                             'required for the igmp '
                                             'test, but currently empty.'
                                             .format(key))
                igmp_str = jsonutils.dumps(test['igmp_config'])
                test_setup_dict = self.test_setup_dict[test['name']]
                test_setup_dict['config_dict']['igmp_config'] = \
                    jsonutils.loads(igmp_str)

            self.test_setup_dict[test['name']]['aggregate'] = \
                test.get('aggregate')
            self.test_setup_dict[test['name']]['vlan_config'] = \
                test.get('vlan_config')

            if 'offload_nics' in test and test['offload_nics'] is not None:
                self.test_setup_dict[test['name']]['offload_nics'] = \
                    test['offload_nics']

            if 'qos_rules' in test and test['qos_rules'] is not None:
                self.test_setup_dict[test['name']]['qos_rules'] = \
                    jsonutils.loads(jsonutils.dumps(test['qos_rules']))

        if not os.path.exists(
                CONF.nfv_plugin_options.external_resources_output_file):
            # iterate flavors_id
            for test, test_param in iter(self.test_setup_dict.items()):
                if 'flavor' in test_param:
                    for flavor in flavors:
                        if test_param['flavor'] == flavor['name']:
                            self.test_setup_dict[test]['flavor-id'] = flavor[
                                'id']

            # iterate image_id
            for test, test_param in iter(self.test_setup_dict.items()):
                if 'image' in test_param:
                    for image in images:
                        if test_param['image'] == image['name']:
                            self.test_setup_dict[test]['image-id'] = \
                                image['id']

        # iterate flavors parameters
        if 'test-flavors' in self.external_config:
            for flavor in self.external_config['test-flavors']:
                self.test_flavor_dict[flavor['name']] = flavor

        if 'test_instance_repo' in self.external_config:
            self.test_instance_repo = self.external_config[
                'test_instance_repo']

        if 'user_data' in CONF.nfv_plugin_options:
            self.user_data = CONF.nfv_plugin_options.user_data
            self.assertTrue(os.path.exists(self.user_data),
                            "Specified user_data file can't be read")
        # Update the floating IP configuration (enable/disable)
        self.fip = self.external_config.get('floating_ip', True)

    def check_flavor_existence(self, testname):
        """Check test specific flavor existence.

        :param testname: value - The name of the running test.
        """
        if 'flavor' and 'flavor-id' in self.test_setup_dict[testname]:
            self.flavor_ref = self.test_setup_dict[testname]['flavor-id']
            return True
        return False

    def _get_dumpxml_instance_data(self, server, hypervisor):
        """Get dumpxml data from the instance

        :param server: Server name
        :param hypervisor: Hypervisor that hold the instance

        :return dumpxml_string
        """

        server_details = \
            self.os_admin.servers_client.show_server(server['id'])['server']
        osp_release = self.get_osp_release(hypervisor)
        # If OSP version is 16, use podman container to retrieve instance XML
        if osp_release >= 16:
            cmd = ('sudo podman exec -it nova_libvirt virsh -c '
                   'qemu:///system dumpxml {}')
        else:
            cmd = 'sudo virsh -c qemu:///system dumpxml {}'
        get_dumpxml = \
            cmd.format(server_details['OS-EXT-SRV-ATTR:instance_name'])
        dumpxml_data = _run_command_over_ssh(hypervisor, get_dumpxml)
        dumpxml_string = ELEMENTTree.fromstring(dumpxml_data)

        return dumpxml_string

    def get_instance_vcpu(self, instance, hypervisor):
        """Get a list of vcpu cores used by the instance

        :param instance
        :param hypervisor
        :return list of instance vcpu
        """
        dumpxml_string = self._get_dumpxml_instance_data(instance, hypervisor)
        vcpupin = dumpxml_string.findall('./cputune/vcpupin')
        vcpu_list = [(vcpu.get('cpuset'))
                     for vcpu in vcpupin if vcpu is not None]
        if ',' in vcpu_list[0]:
            split_list = [vcpu.split(',') for vcpu in vcpu_list if ',' in vcpu]
            vcpu_list = [vcpu for sublist in split_list for vcpu in sublist]
        vcpu_list = [int(vcpu) for vcpu in vcpu_list]
        return list(set(vcpu_list))

    def match_vcpu_to_numa_node(self, instance, hypervisor, numa_node='0'):
        """Verify that provided vcpu list resides within the specified numa

        :param instance: The instance that should check the vcpu on
        :param hypervisor: Check cores on specified hypervisor (ip address)
        :param numa_node: Specify the numa node to check vcpu in
                          String choices: 0, 1, mix
        """
        # In case of mix topology checking only node0 and verifying
        # dumpxml_vcpu_list > hyper_vcpu_list
        mix_mode = True if numa_node == 'mix' else False

        dumpxml_vcpu_list = self.get_instance_vcpu(instance, hypervisor)
        bash_array = " ".join(['{}'.format(x) for x in dumpxml_vcpu_list])
        cmd = '''
        array=( {cpu_list} ); for i in "${{array[@]}}";do
        if [ -d /sys/devices/system/cpu/cpu$i/node{cell} ];then
        echo $i; fi; done'''.format(cell=numa_node, cpu_list=bash_array)
        hyper_vcpu_list = _run_command_over_ssh(hypervisor, cmd).split()
        hyper_vcpu_list = [int(core) for core in hyper_vcpu_list]
        # !!! In case of Mix search for hyper_vcpu_list smaller than vcpu_list
        if mix_mode:
            self.assertIsNot(len(hyper_vcpu_list), len(dumpxml_vcpu_list),
                             'Number of mix vCPUs on numa node {numa} is equal'
                             ' to config {result}'.format(
                                 numa=numa_node, result=hyper_vcpu_list))
        else:
            self.assertEqual(hyper_vcpu_list, dumpxml_vcpu_list,
                             'Number of vCPUs on numa node {numa} does not '
                             'match to config {result}'.format(
                                 numa=numa_node, result=hyper_vcpu_list))

    def _check_numa_from_dumpxml(self, server, hypervisor):
        """Instance number of cells check

        This method checks the number of cells within the provided dumpxml data

        :param server
        :param hypervisor
        """
        dumpxml_string = self._get_dumpxml_instance_data(server, hypervisor)

        dumpxml = dumpxml_string.findall('cpu')[0]
        for i in dumpxml.findall('topology')[0].items():
            if i[0] == 'sockets':
                # change to 2
                self.assertEqual(i[1], '1')
                print(i[0])
        count = 0
        for i in dumpxml.findall('numa')[0].findall('cell'):
            # change memory to 1572864
            if (('id', '0') in i.items() and (
                    ('memory', '2097152')) in i.items()):
                count += 1
            # change cell id to 1 memory to 524288
            if (('id', '1') in i.items() and (
                    ('memory', '2097152')) in i.items()):
                count += 1
        self.assertEqual(count, '2')

    def _check_emulatorpin_from_dumpxml(self, server, hypervisor):
        """Emulatorpin configuration on the instance

        :param server
        :param hypervisor
        """

        dumpxml_string = self._get_dumpxml_instance_data(server, hypervisor)

        cputune = dumpxml_string.findall('cputune')[0]
        emulatorpin_str = cputune.findall('emulatorpin')[0].items()[0][1]

        return emulatorpin_str

    def _check_rx_tx_from_dumpxml(self, server, hypervisor):
        """RX/TX configuration on the instance

        :param server
        :param hypervisor

        :return rx_tx_list
        """

        dumpxml_string = self._get_dumpxml_instance_data(server, hypervisor)

        devices = dumpxml_string.findall('devices')[0]
        rx_tx_list = []
        for value in devices.findall('interface')[0].findall(
                'driver')[0].items():
            rx_tx_list.append(value[1])

        return ','.join(rx_tx_list)

    def locate_dedicated_and_shared_cpu_set(self, node=None, keys=None):
        """Locate dedicated and shared cpu set

        The method locates the cpus provided by the compute for the instances.
        The cpus divided into two groups: dedicated and shared

        :param node: The node that the query should executed on.
        :param keys: The hiera mapping that should be queried.
        :return Two lists of dedicated and shared cpus set
        """
        if not node:
            hyper_kwargs = {'shell': '/home/stack/stackrc'}
            node = self._get_hypervisor_ip_from_undercloud(**hyper_kwargs)[0]
        if not keys:
            hiera_dedicated_cpus = "nova::compute::cpu_dedicated_set"
            hiera_shared_cpus = "nova::compute::cpu_shared_set"
            keys = [hiera_dedicated_cpus, hiera_shared_cpus]
        dedicated, shared = _retrieve_content_from_hiera(node=node,
                                                         keys=keys)
        dedicated = dedicated.strip('[""]')
        dedicated = parse_int_ranges_from_number_string(dedicated)
        shared = shared.strip('[]').split(', ')
        shared = [int(vcpu) for vcpu in shared]
        return dedicated, shared

    def locate_numa_aware_networks(self, numa_physnets):
        """Locate numa aware networks

        :param numa_physnets: Dict of numa aware and non aware physnets
        :return numa_aware_net aware and non aware dict
        """
        numa_aware_net = self.networks_client.list_networks(
            **{'provider:physical_network': numa_physnets['numa_aware_net'],
               'router:external': False})['networks']
        if numa_aware_net:
            numa_aware_net = numa_aware_net[0]['id']
        else:
            nets = self.networks_client.list_networks(
                **{'router:external': False})['networks']
            for net in nets:
                if net['provider:network_type'] == 'vxlan':
                    numa_aware_net = net['id']
        return numa_aware_net

    def compare_emulatorpin_to_overcloud_config(self, server, overcloud_node,
                                                config_path, check_section,
                                                check_value):
        """Compare emulatorpin to overcloud config

        :param server
        :param overcloud_node
        :param config_path
        :param check_section
        :param check_value
        """

        instance_emulatorpin = \
            self._check_emulatorpin_from_dumpxml(server, overcloud_node)
        nova_emulatorpin = _get_value_from_ini_config(overcloud_node,
                                                      config_path,
                                                      check_section,
                                                      check_value)
        # Construct a list of integers of instance emulatorpin threads
        parsed_instance_emulatorpin = \
            parse_int_ranges_from_number_string(instance_emulatorpin)

        # Construct a list of integers of nova emulator pin threads
        parsed_nova_emulatorpin = \
            parse_int_ranges_from_number_string(nova_emulatorpin)

        # Check if all parsed instance emulatorpin threads are part of
        # configured nova emulator pin threads
        if set(parsed_instance_emulatorpin).issubset(parsed_nova_emulatorpin):
            return True
        return False

    def compare_rx_tx_to_overcloud_config(self, server, overcloud_node,
                                          config_path, check_section,
                                          check_value):
        """Compare RX/TX to overcloud config

        :param server
        :param overcloud_node
        :param config_path
        :param check_section
        :param check_value
        """

        instance_rx_tx = self._check_rx_tx_from_dumpxml(server, overcloud_node)
        nova_rx_tx = _get_value_from_ini_config(overcloud_node,
                                                config_path,
                                                check_section,
                                                check_value)

        if instance_rx_tx == nova_rx_tx:
            return True
        return False

    def _check_number_queues(self):
        """This method checks the number of max queues"""
        self.ip_address = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc'})
        ovs_process_pid = self._check_pid_ovs(self.ip_address[0])
        count_pmd = "ps -T -p {} | grep pmd | wc -l".format(ovs_process_pid)
        numpmds = int(_run_command_over_ssh(self.ip_address[0],
                                            count_pmd))
        # We ensure that a number is being parsed, otherwise we fail
        cmd = r'sudo ovs-vsctl show | sed -n "s/.*n_rxq=.\([1-9]\).*/\\1/p"'
        numqueues = (_run_command_over_ssh(self.ip_address[0],
                                           cmd)).encode('ascii', 'ignore')
        if not isinstance(numqueues, type(str())):
            numqueues = numqueues.decode("utf-8")
        msg = "There are no queues available"
        self.assertNotEqual((numqueues.rstrip("\n")), '', msg)
        # Different multiple queues is not a supported scenario as per now
        self.assertTrue(str.isdigit(numqueues.split("\n")[0]),
                        "Queue recieved is not a digit")
        numqueues = int(numqueues.split("\n")[0])
        maxqueues = numqueues * numpmds
        return maxqueues

    def _prepare_cloudinit_file(self, install_packages=None):
        """This method creates cloud-init file with instance boot config.

        Set params:
        User credentials: user:passwd
        Enable direct (console) root login
        Set default route, add additional interface and restart network
        Configures repository
        :param install_packages: Provide the packages that should be installed.
                         Multiple packages should be separated by comma -
                         iperf,htop,vim
        """
        if not self.user_data:
            self.user_data = '''
                             #cloud-config
                             user: {user}
                             password: {passwd}
                             chpasswd: {{expire: False}}
                             ssh_pwauth: True
                             disable_root: 0
                             '''.format(user=self.instance_user,
                                        passwd=self.instance_pass)
        if (self.test_instance_repo and 'name' in
                self.test_instance_repo):
            repo_name = self.external_config['test_instance_repo']['name']
            repo_url = self.external_config['test_instance_repo']['url']
            repo = '''
                             yum_repos:
                                 {repo_name}:
                                     name: {repo_name}
                                     baseurl: {repo_url}
                                     enabled: true
                                     gpgcheck: false
                    '''.format(repo_name=repo_name,
                               repo_url=repo_url)
            self.user_data = "".join((self.user_data, repo))

        if install_packages is not None:
            header = '''
                             packages:'''
            body = ''
            for package in install_packages:
                body += '''
                             - {package}'''.format(package=package)
            package = "".join((header, body))
            self.user_data = "".join((self.user_data, package))

        # Use cloud-config write_files module to copy files
        if CONF.nfv_plugin_options.transfer_files_src and \
                CONF.nfv_plugin_options.transfer_files_dest:
            LOG.info('Locate tests scripts directory')
            exec_dir = os.path.dirname(os.path.realpath(__file__))
            scripts_dir = os.path.join(
                exec_dir, CONF.nfv_plugin_options.transfer_files_src)
            test_scripts = os.listdir(scripts_dir)
            test_scripts = [fil for fil in test_scripts if fil.endswith('.py')]

            header = '''
                             write_files:'''
            body = ''
            for file_content in test_scripts:
                file_dest = os.path.join(
                    CONF.nfv_plugin_options.transfer_files_dest, file_content)
                # The "custom_net_config" script should be placed in a
                # separate location to be executed on every boot.
                if file_content == 'custom_net_config.py':
                    file_dest = '/var/lib/cloud/scripts/per-boot/' \
                                'custom_net_config.py'
                with open(os.path.join(scripts_dir, file_content), 'r') as f:
                    content = f.read().encode('utf8')
                    content = str(base64.b64encode(content).decode('ascii'))
                    body += '''
                               - path: {file_dest}
                                 owner: root:root
                                 permissions: 0755
                                 encoding: base64
                                 content: |
                                     {file_content}
                            '''.format(file_dest=file_dest,
                                       file_content=content)
            files = "".join((header, body))
            self.user_data = "".join((self.user_data, files))

        user_data = textwrap.dedent(self.user_data).lstrip().encode('utf8')
        self.user_data_b64 = base64.b64encode(user_data)
        return self.user_data_b64

    def copy_file_to_remote_host(self, host, ssh_key, username=None,
                                 files=None, src_path=None, dst_path=None,
                                 timeout=60):
        """The method copy provided file to a specified remote host.

        Note! - The method is temporary. Should be removed once config_drive is
        implemented.

        :param host: Remote host to copy files to
        :param username: Username for the remote  host
        :param ssh_key: SSH key for the remote host
        :param files: File or comma separated file to copy
        :param src_path: Source path of the files
        :param dst_path: Destination path of the files
        :param timeout: A timeout for SSH connection to become active
        :return Return local and remote path
        """
        result = None
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        private_key_file = StringIO()
        private_key_file.write(ssh_key)
        private_key_file.seek(0)
        ssh_key = paramiko.RSAKey.from_private_key(private_key_file)

        if username is None:
            username = self.instance_user

        timeout_start = time.time()
        ssh_success = False
        while time.time() < timeout_start + timeout:
            time.sleep(2)
            try:
                ssh.connect(host, username=username, pkey=ssh_key)
                ssh_success = True
                break
            except paramiko.ssh_exception.NoValidConnectionsError:
                print('SSH transport is not ready...')
                continue
        if not ssh_success:
            raise lib_exc.TimeoutException('Instance ssh connection timed out')

        try:
            if not all([files, src_path, dst_path]):
                raise NameError('The following variables must be provided '
                                '- files, src_path, dst_path.')
        except NameError:
            raise

        sftp = ssh.open_sftp()
        for copy_file in files.split(','):
            path = os.path.dirname(__file__)
            src_path = os.path.join(path, src_path)
            file_local = src_path + '/' + copy_file
            file_remote = dst_path + '/' + copy_file

            sftp.put(file_local, file_remote)
            result = 'Copied ' + file_local + ' to ' + host + ':' + file_remote

        sftp.close()
        ssh.close()
        return result

    def ping_via_network_namespace(self, ping_to_ip, network_id):
        cmd = ("sudo ip netns exec qdhcp-" + network_id
               + " ping -c 10 " + ping_to_ip)
        ctrl_ip = urlparse(CONF.identity.uri).netloc.split(':')[0]
        result = _run_command_over_ssh(ctrl_ip, cmd)
        for line in result.split('\n'):
            if 'packets transmitted' in line:
                LOG.info("Ping via namespace result: %s", line)
                received_str = line.split(',')[1].strip()
                try:
                    received = int(received_str.split(' ')[0])
                except ValueError:
                    break
                if received > 0:
                    return True
                break
        return False

    def _read_and_validate_external_resources_data_file(self):
        """Validate yaml file contains externally created resources"""
        LOG.info("Found external resources file. Validating...")
        with open(CONF.nfv_plugin_options.external_resources_output_file,
                  'r') as f:
            try:
                self.external_resources_data = yaml.safe_load(f)
            except yaml.YAMLError as exc:
                pm = exc.problem_mark
                raise Exception('The {} file has an issue on line {} at '
                                'position {}.'.format(pm.name,
                                                      pm.line,
                                                      pm.column))

        if self.external_resources_data['key_pair'] is None or not \
                os.path.exists(self.external_resources_data['key_pair']):
            raise Exception('The private key is missing from the yaml file.')
        for srv in self.external_resources_data['servers']:
            if not set(srv.keys()) >= {'name', 'id', 'fip', 'groups'}:
                raise ValueError('The yaml file missing of the following keys:'
                                 ' name, id or fip.')

    def _organize_external_created_resources(self, group=None):
        """Organize the external created resource by test groups"""
        groups = {}
        bulk_servers = self.external_resources_data['servers']
        for srv in bulk_servers:
            for grp in srv['groups']:
                if grp in groups:
                    groups[grp].append(srv)
                else:
                    groups[grp] = [srv]
        if group not in groups:
            raise ValueError('The required group - "{}" is missing on '
                             'existing resources'.format(group))
        servers = groups[group]

        with open(self.external_resources_data['key_pair'], 'r') as key:
            key_pair = {'private_key': key.read()}
        return servers, key_pair

    def get_ovs_interface_statistics(self, interfaces, previous_stats=None,
                                     hypervisor=None):
        """This method get ovs interface statistics

        :param interfaces: interfaces in which statistics will be retrieved
        :param previous_stats: get the difference between current stats and
                               previous stats
        :param hypervisor: hypervisor ip, if None it will be selected the first
                           one
        :return statistics
        """
        self.ip_address = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc'})
        hypervisor_ip = self.ip_address[0]
        if hypervisor is not None:
            if hypervisor not in self.ip_address:
                raise ValueError('invalid hypervisor ip {}, not in {}'
                                 .format(hypervisor,
                                         ' '.join(self.ip_address)))
            else:
                hypervisor_ip = hypervisor

        self._check_pid_ovs(hypervisor_ip)
        # We ensure that a number is being parsed, otherwise we fail
        statistics = {}
        for interface in interfaces:
            command = 'sudo ovs-vsctl get Interface {} ' \
                      'statistics'.format(interface)
            statistics[interface] = yaml.safe_load(_run_command_over_ssh(
                hypervisor_ip, command).replace('"', '')
                .replace('{', '{"').replace(', ', ', "')
                .replace('=', '":'))
            if previous_stats is not None and \
               interface in previous_stats.keys():
                for stat in statistics[interface].keys():
                    if stat in previous_stats[interface].keys():
                        statistics[interface][stat] -= \
                            previous_stats[interface][stat]
                    else:
                        raise ValueError('missing ovs interface stat {} '
                                         'to compare'.format(stat))

        return statistics

    def get_ovs_multicast_groups(self, switch, multicast_ip=None,
                                 hypervisor=None):
        """This method get ovs multicast groups

        :param switch: ovs switch to get multicast groups
        :param multicast_ip: filter by multicast ip
        :param hypervisor: hypervisor ip, if None it will be selected the first
                           one
        :return multicast groups
        """
        self.ip_address = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc'})
        hypervisor_ip = self.ip_address[0]
        if hypervisor is not None:
            if hypervisor not in self.ip_address:
                raise ValueError('invalid hypervisor ip {}, not in {}'
                                 .format(hypervisor,
                                         ' '.join(self.ip_address)))
            else:
                hypervisor_ip = hypervisor

        self._check_pid_ovs(hypervisor_ip)

        command = 'sudo ovs-appctl mdb/show {}'.format(switch)
        output = list(filter(None, _run_command_over_ssh(
            hypervisor_ip, command).split('\n')))
        fields = None
        output_data = []
        for line in output:
            data = list(filter(None, line.split(" ")))
            if fields is None:
                fields = data
            else:
                data = dict(zip(fields, data))
                if multicast_ip is None or \
                   multicast_ip is not None and data['GROUP'] == multicast_ip:
                    output_data.append(data)
        return output_data

    def _get_hypervisor_host_ip(self, name=None):
        """Get hypervisor ip

        This Method lists aggregation based on name,
        and returns the aggregated search for IP through Hypervisor list API
        Add support in case of NoAggregation, and Hypervisor list is not empty
        if host=None, no aggregation, or name=None and if hypervisor list has
        one member return the member

        :param name
        """
        host = None
        ip_address = ''
        if name:
            host = self._list_aggregate(name)

        hyper = self.manager.hypervisor_client.list_hypervisors()
        if host:
            for i in hyper['hypervisors']:
                if i['hypervisor_hostname'] == host:
                    ip_address = \
                        self.manager.hypervisor_client.show_hypervisor(
                            i['id'])['hypervisor']['host_ip']
        else:
            for i in hyper['hypervisors']:
                if i['state'] == 'up':
                    ip_address = \
                        self.manager.hypervisor_client.show_hypervisor(
                            i['id'])['hypervisor']['host_ip']
        return ip_address

    def _get_hypervisor_ip_from_undercloud(self, **kwargs):
        """This Method lists aggregation based on name

        Returns the aggregated search for IP through Hypervisor list API
        Add support in case of NoAggregation, and Hypervisor list is not empty
        if host=None, no aggregation, or name=None and if hypervisor list has
        one member return the member
        :param kwargs['shell']
        :param kwargs['server_id']
        :param kwargs['aggregation_name']
        :param kwargs['hyper_name']
        """
        host = None
        ip_address = ''
        if 'aggregation_name' in kwargs:
            host = self._list_aggregate(kwargs['aggregation_name'])

        hyper = self.manager.hypervisor_client.list_hypervisors()
        """
        if hosts in aggregations
        """
        if host:
            host_name = re.split(r"\.", host[0])[0]
            if host_name is None:
                host_name = host

            for i in hyper['hypervisors']:
                if i['hypervisor_hostname'] == host[0]:
                    command = 'openstack ' \
                              'server show ' + host_name + \
                              ' -c \'addresses\' -f value | cut -d\"=\" -f2'
                    ip_address = \
                        _run_local_cmd_shell_with_venv(command,
                                                       kwargs['shell'])
        else:
            """
            no hosts in aggregations, select with 'server_id' in kwargs
            """
            compute = 'compute'
            if 'hyper_name' in kwargs:
                compute = kwargs['hyper_name']
            if 'server_id' in kwargs:
                server = self. \
                    os_admin.servers_client.show_server(kwargs['server_id'])
                compute = \
                    server['server']['OS-EXT-SRV-ATTR:host'].partition('.')[0]

            for i in hyper['hypervisors']:
                if i['state'] == 'up':
                    if i['hypervisor_hostname'].split(".")[0] == compute:
                        compute = i['hypervisor_hostname'].split(".")[0]
                    command = 'openstack server list -c \'Name\' -c ' \
                              '\'Networks\' -f value | grep -i {0} | ' \
                              'cut -d\"=\" -f2'.format(compute)
                    ip_address = \
                        _run_local_cmd_shell_with_venv(command,
                                                       kwargs['shell'])

        return ip_address

    def locate_ovs_physnets(self, node=None, keys=None):
        """Locate ovs existing physnets

        The method locate the ovs existing physnets and create a dict with
        the numa aware and non aware physnets.

        :param node: The node that the query should executed on.
        :param keys: The hiera mapping that should be queried.
        :return The numa physnets dict is returned
        """
        if node is None:
            hyper_kwargs = {'shell': '/home/stack/stackrc'}
            node = self._get_hypervisor_ip_from_undercloud(**hyper_kwargs)[0]
        if not keys:
            hiera_bridge_mapping = "neutron::agents::ml2::ovs::bridge_mappings"
            hiera_numa_mapping = "nova::compute::neutron_physnets_numa_" \
                                 "nodes_mapping"
            hiera_numa_tun = "nova::compute::neutron_tunnel_numa_nodes"
            keys = [hiera_bridge_mapping, hiera_numa_mapping, hiera_numa_tun]
        numa_phys_content = _retrieve_content_from_hiera(node=node,
                                                         keys=keys)
        # Identify the numa aware physnet
        numa_aware_phys = None
        bridge_mapping = None
        numa_aware_tun = None
        for physnet in numa_phys_content:
            if '=>' in physnet:
                numa_aware_phys = yaml.safe_load(physnet.replace('=>', ':'))
            elif ':' in physnet:
                bridge_mapping = yaml.safe_load(physnet)
            else:
                numa_aware_tun = yaml.safe_load(physnet)

        numa_physnets = {}
        physnet_list = []
        # In order to minimize the amount of remote ssh access, first the
        # remote commands are grouped to one single command and then the
        # remote command performed once.
        ovs_cmd_template = 'sudo ovs-vsctl get Bridge {} datapath-type;'
        ovs_cmd = ''
        for item in bridge_mapping:
            s = item.split(':')
            physnet = s[0]
            bridge = s[1]
            ovs_cmd += ovs_cmd_template.format(bridge)
            physnet_list.append(physnet)

        dpath_type = \
            _run_command_over_ssh(node, ovs_cmd).strip('\n').split('\n')
        physnet_dict = dict(zip(physnet_list, dpath_type))
        for physnet, dpath in physnet_dict.items():
            LOG.info('The {} network has the {} datapath'.format(physnet,
                                                                 dpath))
            if dpath == 'netdev' and physnet in numa_aware_phys.keys():
                LOG.info('The {} is a numa aware network'.format(physnet))
                numa_physnets['numa_aware_net'] = physnet
            if dpath == 'netdev' and physnet not in numa_aware_phys.keys():
                LOG.info('The {} is a non numa aware network'.format(physnet))
                numa_physnets['non_numa_aware_net'] = physnet

        if numa_aware_tun is not None:
            numa_physnets['numa_aware_tunnel'] = numa_aware_tun[0]
        return numa_physnets
