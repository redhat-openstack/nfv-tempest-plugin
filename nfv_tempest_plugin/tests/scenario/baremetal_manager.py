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
from tempest.api.compute import api_microversion_fixture
from tempest.common import waiters
from tempest import config
from tempest.lib.common import api_version_utils
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc
from tempest.scenario import manager
"""Python 2 and 3 support"""
from six.moves.configparser import ConfigParser
from six.moves import StringIO
from six.moves.urllib.parse import urlparse

CONF = config.CONF
LOG = log.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class BareMetalManager(api_version_utils.BaseMicroversionTest,
                       manager.ScenarioTest):
    """This class Interacts with BareMetal settings"""
    credentials = ['primary', 'admin']

    def __init__(self, *args, **kwargs):
        super(BareMetalManager, self).__init__(*args, **kwargs)
        self.public_network = CONF.network.public_network_id
        self.instance_user = CONF.nfv_plugin_options.instance_user
        self.instance_pass = CONF.nfv_plugin_options.instance_pass
        self.flavor_ref = CONF.compute.flavor_ref
        self.cpuregex = re.compile('^[0-9]{1,2}$')
        self.external_config = None
        self.test_setup_dict = {}
        self.key_pairs = {}
        self.servers = []
        self.test_network_dict = {}
        self.test_flavor_dict = {}
        self.test_instance_repo = {}
        self.user_data = {}
        self.fip = True
        self.external_resources_data = None

    @classmethod
    def setup_clients(cls):
        super(BareMetalManager, cls).setup_clients()
        cls.hypervisor_client = cls.manager.hypervisor_client
        cls.aggregates_client = cls.manager.aggregates_client

    def setUp(self):
        """Check hypervisor configuration:

        SSH user and Private key/password definition [must].
        External config file exist [not a must].
        """
        super(BareMetalManager, self).setUp()
        self.assertIsNotNone(CONF.nfv_plugin_options.overcloud_node_user,
                             "Missing SSH user login in config")

        if CONF.nfv_plugin_options.overcloud_node_pkey_file:
            key_str = open(
                CONF.nfv_plugin_options.overcloud_node_pkey_file).read()
            CONF.nfv_plugin_options.overcloud_node_pkey_file_rsa = \
                paramiko.RSAKey.from_private_key(StringIO(key_str))
        else:
            self.assertIsNotNone(
                CONF.nfv_plugin_options.overcloud_node_pass,
                'Missing SSH password or key_file')
        if CONF.nfv_plugin_options.external_config_file:
            if os.path.exists(CONF.nfv_plugin_options.external_config_file):
                self.read_external_config_file()

        self.useFixture(api_microversion_fixture.APIMicroversionFixture(
            self.request_microversion))

        if CONF.nfv_plugin_options.external_resources_output_file:
            if os.path.exists(
                    CONF.nfv_plugin_options.external_resources_output_file):
                self._read_and_validate_external_resources_data_file()

        if CONF.nfv_plugin_options.quota_cores and \
                CONF.nfv_plugin_options.quota_ram:
            self.os_admin.quotas_client.update_quota_set(
                self.os_primary.tenants_client.tenant_id,
                cores=CONF.nfv_plugin_options.quota_cores,
                ram=CONF.nfv_plugin_options.quota_ram)

    @classmethod
    def resource_setup(cls):
        super(BareMetalManager, cls).resource_setup()
        cls.tenant_id = cls.manager.identity_client.tenant_id
        cls.request_microversion = (
            api_version_utils.select_request_microversion(
                cls.min_microversion,
                CONF.compute.min_microversion))

    @classmethod
    def setup_credentials(cls):
        super(BareMetalManager, cls).setup_credentials()

    def _get_number_free_hugepages(self, host):
        """Free memory pages number

        This Method Connects to Bare Metal and receive Number of free
        Memory Pages BareMetal on Bare Metal settings
        """
        command = "cat /sys/kernel/mm/hugepages/hugepages-1048576kB/" \
                  "free_hugepages"
        hugepages = self._run_command_over_ssh(host, command)
        return hugepages

    def read_external_config_file(self):
        """This Method reads network_config.yml

        Reads config data and assign it to dictionaries
        """
        with open(CONF.nfv_plugin_options.external_config_file, 'r') as f:
            self.external_config = yaml.load(f)

        if not os.path.exists(
                CONF.nfv_plugin_options.external_resources_output_file):
            """Hold flavor, net and images lists"""
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
                        self.test_network_dict[net]['net-id'] = network['id']

        # Insert here every new parameter.
        for test in self.external_config['tests-setup']:
            if 'flavor' in test and test['flavor'] is not None:
                self.test_setup_dict[test['name']] = {'flavor': test['flavor']}
            if 'package-names' in test and test['package-names'] is not None:
                self.test_setup_dict[test['name']] = \
                    {'package-names': test['package-names']}
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
            self.test_setup_dict[test['name']]['aggregate'] = \
                test.get('aggregate')

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

    def create_flavor(self, name='flavor', ram='2048', disk='20', vcpus='1',
                      **flavor_args):
        """The method creates flavor based on the args passed to the method.

        The flavor could be created with or without an extra specs.
        In case method call with empty parameters, default values will
        be used and default flavor will be created.

        :param name: Flavor name.
        :param ram: Flavor ram.
        :param disk: Flavor disk.
        :param vcpus: Flavor vcpus.
        :param flavor_args: Dict of parameters for the flavor that should be
                created.
        :return flavor_id: ID of the created flavor.
        """
        flavor = self.os_admin.flavors_client.create_flavor(name=name,
                                                            ram=ram,
                                                            disk=disk,
                                                            vcpus=vcpus)
        flavor_id = flavor['flavor']['id']
        if 'extra_specs' in flavor_args:
            extra_specs = flavor_args['extra_specs']
            if isinstance(flavor_args['extra_specs'], list):
                extra_specs = flavor_args['extra_specs'][0]
            self.os_admin.flavors_client.set_flavor_extra_spec(flavor_id,
                                                               **extra_specs)
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        self.os_admin.flavors_client.delete_flavor, flavor_id)
        return flavor_id

    def _get_dumpxml_instance_data(self, server, hypervisor):
        """Get dumpxml data from the instance

        :param server: Server name
        :param hypervisor: Hypervisor that hold the instance

        :return dumpxml_string
        """

        server_details = \
            self.os_admin.servers_client.show_server(server['id'])['server']
        get_dumpxml = 'sudo virsh -c qemu:///system dumpxml {0}'.format(
            server_details['OS-EXT-SRV-ATTR:instance_name'])
        dumpxml_data = self._run_command_over_ssh(hypervisor, get_dumpxml)
        dumpxml_string = ELEMENTTree.fromstring(dumpxml_data)

        return dumpxml_string

    def _check_vcpu_from_dumpxml(self, server, hypervisor, cell_id='0'):
        """Instance vcpu check

        This method checks vcpu value within the provided dumpxml data

        :param server
        :param hypervisor
        :param cell_id
        """

        dumpxml_string = self._get_dumpxml_instance_data(server, hypervisor)

        dumpxml = dumpxml_string.findall('cputune')[0]
        pinned_cpu_list = []
        for numofcpus in dumpxml.findall('vcpupin'):
            self.assertFalse(self.cpuregex.match(
                numofcpus.items()[1][1]) is None)
            pinned_cpu_list.append(numofcpus.items()[1][1])
        format_list = " ".join(['{}'.format(x) for x in pinned_cpu_list])

        """
        In case of mix topology checking only node0 and verifying
        pinned_cpu_list > res.split()
        """
        mix_mode = 'mix' if cell_id == 'mix' else cell_id

        command = '''
        array=( {cpu_list} ); for i in "${{array[@]}}";do
        if [ -d /sys/devices/system/cpu/cpu$i/node{cell} ];then
        echo $i; fi; done'''.format(cell=cell_id, cpu_list=format_list)
        res = self._run_command_over_ssh(hypervisor, command)
        # !!! In case of Mix search for res smaller than pinned_cpu_list
        if mix_mode != 'mix':
            self.assertEqual(res.split(), pinned_cpu_list,
                             'number of vCPUs on cell '
                             '{cell} does not match to config {result}'.format(
                                 cell=cell_id, result=res.split))
        else:
            self.assertIsNot(len(res.split()), len(pinned_cpu_list),
                             'number of mix vCPUs on cell '
                             '{cell} is equal to config {result}'.format(
                                 cell=cell_id, result=res.split))

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

    def _get_overcloud_config(self, overcloud_node, config_path):
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
        config_data = self._run_command_over_ssh(overcloud_node,
                                                 get_config_data)

        return config_data

    def _get_value_from_ini_config(self, overcloud_node, config_path,
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

        ini_config = self._get_overcloud_config(overcloud_node, config_path)
        # Python 2 and 3 support
        get_value = ConfigParser(allow_no_value=True)
        if sys.version_info[0] > 2:
            get_value = ConfigParser(allow_no_value=True, strict=False)
        get_value.readfp(StringIO(ini_config))
        value_data = []
        for value in check_value.split(','):
            value_data.append(get_value.get(check_section, value))

        return ','.join(value_data)

    def _retrieve_content_from_files(self, node, files):
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

        guest_content = self._run_command_over_ssh(node, cmd).split('\n')
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

    def _retrieve_content_from_hiera(self, node, keys,
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
        hiera_content = self._run_command_over_ssh(node, hiera_command)
        hiera_content = hiera_content.split('\n')[:-1]
        return hiera_content

    def locate_ovs_networks(self, node, keys=None):
        """Locate ovs existing networks

        The method locate the ovs existing networks and create a dict with
        the numa aware and non aware nets.

        :param node: The node that the query should executed on.
        :param keys: The hiera mapping that should be queried.
        :return The numa network dict is returned
        """
        if not keys:
            hiera_bridge_mapping = "neutron::agents::ml2::ovs::bridge_mappings"
            hiera_numa_mapping = "nova::compute::neutron_physnets_numa_" \
                                 "nodes_mapping"
            keys = [hiera_bridge_mapping, hiera_numa_mapping]
        numa_net_content = self._retrieve_content_from_hiera(node=node,
                                                             keys=keys)
        # Identify the numa aware physnet
        numa_aware_net = None
        bridge_mapping = None
        for physnet in numa_net_content:
            if '=>' in physnet:
                numa_aware_net = yaml.safe_load(physnet.replace('=>', ':'))
            else:
                bridge_mapping = yaml.safe_load(physnet)

        numa_networks = {}
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
            self._run_command_over_ssh(node, ovs_cmd).strip('\n').split('\n')
        physnet_dict = dict(zip(physnet_list, dpath_type))
        for physnet, dpath in physnet_dict.items():
            LOG.info('The {} network has the {} datapath'.format(physnet,
                                                                 dpath))
            if dpath == 'netdev' and physnet in numa_aware_net.keys():
                LOG.info('The {} is a numa aware network'.format(physnet))
                numa_networks['numa_aware_net'] = physnet
            if dpath == 'netdev' and physnet not in numa_aware_net.keys():
                LOG.info('The {} is a non numa aware network'.format(physnet))
                numa_networks['non_numa_aware_net'] = physnet
        return numa_networks

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
        nova_emulatorpin = self._get_value_from_ini_config(overcloud_node,
                                                           config_path,
                                                           check_section,
                                                           check_value)
        instance_emulatorpin = sorted(instance_emulatorpin.replace('-', ',')
                                      .split(','))
        nova_emulatorpin = sorted(nova_emulatorpin.split(','))

        if instance_emulatorpin == nova_emulatorpin:
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
        nova_rx_tx = self._get_value_from_ini_config(overcloud_node,
                                                     config_path,
                                                     check_section,
                                                     check_value)

        if instance_rx_tx == nova_rx_tx:
            return True
        return False

    @staticmethod
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

    def _run_local_cmd_shell_with_venv(self, command, shell_file_to_exec=None):
        """This Method runs command on tester local host

        Shell_file_to_exec path to source file default is None
        TBD: Add support to return, hosts list
        TBD: Return None in case no aggregation found.

        :param command
        :param shell_file_to_exec
        """
        self.assertNotEmpty(command, "missing command parameter")
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

    def _create_and_set_aggregate(self, aggr_name, hyper_hosts, aggr_meta):
        """Create aggregation and add an hypervisor to it

        :param aggr_name: The name of the aggregation to be created
        :param hyper_hosts: The list of the hypervisors to be attached
        :param aggr_meta: The metadata for the aggregation
        """
        hyper_list = []
        for hyper in self.hypervisor_client.list_hypervisors()['hypervisors']:
            for host in hyper_hosts:
                if hyper['hypervisor_hostname'].split('.')[0] in host:
                    hyper_list.append(hyper['hypervisor_hostname'])
        if not hyper_list:
            raise ValueError('Provided host for the aggregate does not exist.')

        aggr = self.aggregates_client.create_aggregate(name=aggr_name)
        meta_body = {aggr_meta.split('=')[0]: aggr_meta.split('=')[1]}
        self.aggregates_client.set_metadata(aggr['aggregate']['id'],
                                            metadata=meta_body)
        self.addCleanup(self.aggregates_client.delete_aggregate,
                        aggr['aggregate']['id'])

        for host in hyper_list:
            self.aggregates_client.add_host(aggr['aggregate']['id'], host=host)
            self.addCleanup(self.aggregates_client.remove_host,
                            aggr['aggregate']['id'], host=host)
        return aggr['aggregate']['name']

    def _list_aggregate(self, name=None):
        """Aggregation listing

        This Method lists aggregation based on name, and returns the
        aggregated hosts lists.
        TBD: Add support to return, hosts list
        TBD: Return None in case no aggregation found.

        :param name
        """
        host = None

        if not name:
            return host

        aggregate = self.aggregates_client.list_aggregates()['aggregates']
        #       Assertion check
        if aggregate:
            aggr_result = []
            for i in aggregate:
                if name in i['name']:
                    aggr_result.append(self.aggregates_client.
                                       show_aggregate(i['id'])['aggregate'])
            host = aggr_result[0]['hosts']
        return host

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
            host_name = re.split("\.", host[0])[0]
            if host_name is None:
                host_name = host

            for i in hyper['hypervisors']:
                if i['hypervisor_hostname'] == host[0]:
                    command = 'openstack ' \
                              'server show ' + host_name + \
                              ' -c \'addresses\' -f value | cut -d\"=\" -f2'
                    ip_address = self.\
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
                server = self.\
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
                    ip_address = self.\
                        _run_local_cmd_shell_with_venv(command,
                                                       kwargs['shell'])

        return ip_address

    def _create_test_networks(self):
        """Method reads test-networks attributes from external_config.yml

        The network will be created for tempest tenant.
        Do not use this method if the test
        need to run on pre-configured networks..
        see _detect_existing_networks() method
        """
        if len(self.external_config['test-networks']) > 0:
            self.test_network_dict.clear()
        mgmt_network = None
        for net in self.external_config['test-networks']:
            self.test_network_dict[net['name']] = \
                {'provider:physical_network': net['physical_network'],
                 'provider:network_type': net['network_type'],
                 'dhcp': net['enable_dhcp'],
                 'cidr': net['cidr'],
                 'pool_start': net['allocation_pool_start'],
                 'pool_end': net['allocation_pool_end'],
                 'gateway_ip': net['gateway_ip'],
                 'port_type': net['port_type'],
                 'ip_version': net['ip_version']}
            if 'segmentation_id' in net:
                self.test_network_dict[net['name']][
                    'provider:segmentation_id'] = net['segmentation_id']
            if 'sec_groups' in net:
                self.test_network_dict[net['name']]['sec_groups'] = \
                    net['sec_groups']
            if 'mgmt' in net and net['mgmt']:
                mgmt_network = net['name']
            if 'mgmt' in net and 'dns_nameservers' in net:
                self.test_network_dict[net['name']]['dns_nameservers'] = \
                    net['dns_nameservers']
            if ('tag' in net and (2.32 <= float(self.request_microversion) <=
                                  2.36 or self.request_microversion >= 2.42)):
                self.test_network_dict[net['name']]['tag'] = net['tag']
            if 'trusted_vf' in net and net['trusted_vf']:
                self.test_network_dict[net['name']]['trusted_vf'] = True
        network_kwargs = {}
        """
        Create network and subnets
        """
        for net_name, net_param in iter(self.test_network_dict.items()):
            network_kwargs.clear()
            network_kwargs['name'] = net_name
            if 'sec_groups' in net_param and not net_param['sec_groups']:
                network_kwargs['port_security_enabled'] = net_param[
                    'sec_groups']
            """Added this for VxLAN no need of physical network or segmentation
            """
            if 'provider:network_type' in net_param and \
                    (net_param['provider:network_type'] == 'vlan' or
                     net_param['provider:network_type'] == 'flat'):
                if 'provider:physical_network' in net_param:
                    network_kwargs['provider:physical_network'] =\
                        net_param['provider:physical_network']
                if 'provider:segmentation_id' in net_param:
                    network_kwargs['provider:segmentation_id'] =\
                        net_param['provider:segmentation_id']

            if 'provider:network_type' in net_param:
                network_kwargs['provider:network_type'] =\
                    net_param['provider:network_type']

            network_kwargs['tenant_id'] = self.networks_client.tenant_id
            result = self.os_admin.networks_client.create_network(
                **network_kwargs)
            network = result['network']
            self.assertEqual(network['name'], net_name)
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.os_admin.networks_client.delete_network,
                            network['id'])
            network_kwargs.clear()
            network_kwargs['network_id'] = network['id']
            self.test_network_dict[net_name]['net-id'] = network['id']
            network_kwargs['name'] = net_name + '_subnet'
            network_kwargs['ip_version'] = net_param['ip_version']
            if 'cidr' in net_param:
                network_kwargs['cidr'] = net_param['cidr']
            if 'gateway_ip' in net_param:
                network_kwargs['gateway_ip'] = net_param['gateway_ip']
            if 'dhcp' in net_param:
                network_kwargs['enable_dhcp'] = net_param['dhcp']
            if 'pool_start' in net_param:
                network_kwargs['allocation_pools'] = \
                    [{'start': net_param['pool_start'],
                      'end':net_param['pool_end']}]
            if 'dns_nameservers' in net_param:
                network_kwargs['dns_nameservers'] = \
                    net_param['dns_nameservers']

            result = self.subnets_client.create_subnet(**network_kwargs)
            subnet = result['subnet']
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.subnets_client.delete_subnet, subnet['id'])
            self.test_network_dict[net_name]['subnet-id'] = subnet['id']
        if mgmt_network is not None:
            self.test_network_dict['public'] = mgmt_network

    def _add_subnet_to_router(self):
        """Adding subnet as an interface to the router

        For VxLAN network type there is additional fork to be Done
        The following add to admin router mgmt subnet and create flowing ip
        """
        public_name = self.test_network_dict['public']
        public_net = self.test_network_dict[public_name]
        """
        search for admin router name

        """
        seen_routers = self.os_admin.routers_client.list_routers()['routers']
        self.assertEqual(len(seen_routers), 1,
                         "Test require 1 admin router. please check")
        self.os_admin.routers_client.add_router_interface(
            seen_routers[0]['id'], subnet_id=public_net['subnet-id'])
        self.addCleanup(self._try_remove_router_subnet,
                        seen_routers[0]['id'],
                        subnet_id=public_net['subnet-id'])

    def _try_remove_router_subnet(self, router, **kwargs):
        # delete router, if it exists
        try:
            self.os_admin.routers_client.remove_router_interface(
                router, **kwargs)
        # if router is not found, this means it was deleted in the test
        except lib_exc.NotFound:
                pass

    def _detect_existing_networks(self):
        """Use method only when test require no network

        cls.set_network_resources()
        it run over external_config networks,
        verified against existing networks..
        in case all networks exist return True and fill self.test_networks
        lists.
        In case there is external router.. public network decided
        based on router_external=False and router is not None
        """
        self.assertIsNotNone(CONF.nfv_plugin_options.external_config_file,
                             'This test require missing external_config, '
                             'for this test')

        self.assertTrue(self.test_network_dict,
                        'No networks for test, please check '
                        'external_config_file')

        public_network = self.networks_client.list_networks(
            **{'router:external': True})['networks']

        """
        Check public network exist in networks.
        remove it from network list
        if  = 0 we create port on first network if = 1  public network exist
        and set next network as vm management network
        name must not be public, router exist and network external false
        """
        if len(public_network) == 0:
            self.test_network_dict['public'] = self.test_network_dict.keys()[0]

        elif len(public_network) == 1:
            self.test_network_dict['public'] = None
            remove_network = None
            for net_name, net_param in iter(self.test_network_dict.items()):
                if net_name != 'public' and 'router' in net_param \
                        and 'external' in net_param:
                    if not net_param['external']:
                        self.test_network_dict['public'] = net_name
                    else:
                        remove_network = net_name
            self.test_network_dict.pop(remove_network)

    def _create_ports_on_networks(self, num_ports=1, **kwargs):
        """Create ports on a test networks for instances

        The method will create a network ports as per test_network dict
        from the external config file.
        The ports creation will loop over the number of specified servers.
        This will allow to call the method once for all instances.

        The ID of the security groups used for the ports creation, removed
        from the kwargs for the later instance creation.

        :param num_ports: The number of loops for ports creation
        :param kwargs

        :return ports_list: A list of ports lists
        """
        ports_list = []
        """
        set public network first
        """
        for nport in range(num_ports):
            networks_list = []
            for net_name, net_param in iter(self.test_network_dict.items()):
                create_port_body = {'binding:vnic_type': '',
                                    'namestart': 'port-smoke'}
                if 'port_type' in net_param:
                    create_port_body['binding:vnic_type'] = \
                        net_param['port_type']
                    if 'security_groups' in kwargs and net_name == \
                            self.test_network_dict['public']:
                        create_port_body['security_groups'] = \
                            [s['id'] for s in kwargs['security_groups']]
                    if 'trusted_vf' in net_param and \
                       net_param['trusted_vf'] and \
                       net_param['port_type'] == 'direct':
                        create_port_body['binding:profile'] = \
                            {'trusted': 'true'}
                    port = self._create_port(network_id=net_param['net-id'],
                                             **create_port_body)
                    net_var = {'uuid': net_param['net-id'], 'port': port['id']}
                    if 'tag' in net_param:
                        net_var['tag'] = net_param['tag']
                    networks_list.append(net_var) \
                        if net_name != self.test_network_dict['public'] else \
                        networks_list.insert(0, net_var)
            ports_list.append(networks_list)
        if 'security_groups' in kwargs:
            [x.pop('id') for x in kwargs['security_groups']]
        return ports_list

    def _create_port(self, network_id, client=None, namestart='port-quotatest',
                     **kwargs):
        """Port creation for instance

        This Method Overrides Manager::CreatePort to support direct and
        direct ph ports

        :param network_id
        :param client
        :param namestart
        :param kwargs
        """
        kwargs['admin_state_up'] = 'True'
        if not client:
            client = self.ports_client
        name = data_utils.rand_name(namestart)
        result = client.create_port(name=name, network_id=network_id, **kwargs)
        self.assertIsNotNone(result, 'Unable to allocate port')
        port = result['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])
        return port

    def create_server(self, name=None, image_id=None, flavor=None,
                      validatable=False, wait_until=None,
                      wait_on_delete=True, clients=None, **kwargs):
        """This Method Overrides Manager::Createserver to support Gates needs

        :param validatable:
        :param clients:
        :param image_id:
        :param wait_on_delete:
        :param wait_until:
        :param flavor:
        :param name:
        """
        if 'key_name' not in kwargs:
            key_pair = self.create_keypair()
            self.key_pairs[key_pair['name']] = key_pair
            kwargs['key_name'] = key_pair['name']

        net_id = []
        networks = []
        (CONF.compute_feature_enabled.config_drive and
         kwargs.update({'config_drive': True}))
        if 'networks' in kwargs:
            net_id = kwargs['networks']
            kwargs.pop('networks', None)
        else:
            networks = self.networks_client.list_networks(
                **{'router:external': False})['networks']

        for network in networks:
            net_id.append({'uuid': network['id']})

        if 'transfer_files' in CONF.nfv_plugin_options:
            if float(self.request_microversion) < 2.57:
                files = jsonutils.loads(CONF.nfv_plugin_options.transfer_files)
                kwargs['personality'] = []
                for copy_file in files:
                    self.assertTrue(os.path.exists(copy_file['client_source']),
                                    "Specified file {0} can't be read"
                                    .format(copy_file['client_source']))
                    content = open(copy_file['client_source']).read()
                    content = textwrap.dedent(content).lstrip().encode('utf8')
                    content_b64 = base64.b64encode(content)
                    guest_destination = copy_file['guest_destination']
                    kwargs['personality'].append({"path": guest_destination,
                                                  "contents": content_b64})
            else:
                raise Exception("Personality (transfer-files) "
                                "is deprecated from "
                                "compute micro_version 2.57 and onwards")

        server = super(BareMetalManager,
                       self).create_server(name=name,
                                           networks=net_id,
                                           image_id=image_id,
                                           flavor=flavor,
                                           wait_until=wait_until,
                                           **kwargs)
        self.servers.append(server)
        return server

    def create_server_with_resources(self, num_servers=1, num_ports=None,
                                     fip=True, test=None, srv_state='ACTIVE',
                                     use_mgmt_only=False, **kwargs):
        """The method creates multiple instances

        :param num_servers: The number of servers to boot up.
        :param num_ports: The number of ports to the created.
                          Default to (num_servers)
        :param fip: Creation of the floating ip for the server.
        :param test: Currently executed test. Provide test specific parameters.
        :param use_mgmt_only: Boot instances with mgmt net only.
        :param srv_state: The status of the booted instance.
        :param kwargs: See below.

        :return servers, fips
        """
        LOG.info('Creating resources...')
        servers, key_pair = ([], [])

        if num_ports is None:
            num_ports = num_servers

        # Check for the test config file
        self.assertTrue(test in self.test_setup_dict,
                        'The test requires {0} config in external_config_file'.
                        format(test))

        # In case resources created externally, set them.
        if self.external_resources_data is not None:
            servers = self.external_resources_data['servers']
            with open(self.external_resources_data['key_pair'], 'r') as key:
                key_pair = {'private_key': key.read()}
            LOG.info('The resources created by the external tool. '
                     'Continue to the test.')
            return servers, key_pair

        # Create and configure aggregation zone if specified
        if self.test_setup_dict[test]['aggregate'] is not None:
            aggr_hosts = self.test_setup_dict[test]['aggregate']['hosts']
            aggr_meta = self.test_setup_dict[test]['aggregate']['metadata']
            self._create_and_set_aggregate(test, aggr_hosts, aggr_meta)

        # Flavor creation
        if not kwargs.get('flavor'):
            flavor_check = self.check_flavor_existence(test)
            if flavor_check is False:
                flavor_name = self.test_setup_dict[test]['flavor']
                self.flavor_ref = self. \
                    create_flavor(**self.test_flavor_dict[flavor_name])
                kwargs['flavor'] = self.flavor_ref
                LOG.info('The flavor {} has been created'.format(
                    self.flavor_ref))

        LOG.info('Creating networks, keypair, security groups, router and '
                 'prepare cloud init.')
        # Key pair creation
        key_pair = self.create_keypair()
        kwargs['key_name'] = key_pair['name']

        # Network, subnet, router and security group creation
        self._create_test_networks()
        security_groups = self._set_security_groups()
        if security_groups is not None:
            kwargs['security_groups'] = security_groups
        ports_list = self._create_ports_on_networks(num_ports=num_ports,
                                                    **kwargs)
        router_exist = True
        if 'router' in self.test_setup_dict[test]:
            router_exist = self.test_setup_dict[test]['router']
        if router_exist:
            self._add_subnet_to_router()
        # Prepare cloudinit
        kwargs['user_data'] = self._prepare_cloudinit_file()

        for num in range(num_servers):
            kwargs['networks'] = ports_list[num]

            """ If this parameters exist, parse only mgmt network.
            Example live migration can't run with SRIOV ports attached"""
            if use_mgmt_only:
                del (kwargs['networks'][1:])

            LOG.info('Create instance - {}'.format(num + 1))
            servers.append(self.create_server(**kwargs))
        for num, server in enumerate(servers):
            waiters.wait_for_server_status(self.os_admin.servers_client,
                                           server['id'], srv_state)
            LOG.info('The instance - {} is in an {} state'.format(num + 1,
                     srv_state))
            port = self.os_admin.ports_client.list_ports(device_id=server[
                'id'], network_id=ports_list[num][0]['uuid'])['ports'][0]

            if fip:
                server['fip'] = \
                    self.create_floating_ip(server, self.public_network)['ip']
                LOG.info('The {} fip is allocated to the instance'.format(
                    server['fip']))
            else:
                server['fip'] = port['fixed_ips'][0]['ip_address']
                server['network_id'] = ports_list[num][0]['uuid']
                LOG.info('The {} fixed ip set for the instance'.format(
                    server['fip']))
        return servers, key_pair

    def _check_number_queues(self):
        """This method checks the number of max queues"""
        self.ip_address = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc'})
        ovs_process = "sudo pidof ovs-vswitchd"
        ovs_process_pid = (self._run_command_over_ssh(self.ip_address[0],
                                                      ovs_process)).strip('\n')
        if not ovs_process_pid:
            raise ValueError('The ovs-vswitchd process is missing.')
        count_pmd = "ps -T -p {} | grep pmd | wc -l".format(ovs_process_pid)
        numpmds = int(self._run_command_over_ssh(self.ip_address[0],
                                                 count_pmd))
        # We ensure that a number is being parsed, otherwise we fail
        command = 'sudo ovs-vsctl show' \
                  '| sed -n "s/.*n_rxq=.\([1-9]\).*/\\1/p"'
        numqueues = (self._run_command_over_ssh(self.ip_address[0],
                                                command)).encode('ascii',
                                                                 'ignore')
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
        gw_ip = self.test_network_dict[self.test_network_dict[
            'public']]['gateway_ip']

        if not self.user_data:
            self.user_data = '''
                             #cloud-config
                             user: {user}
                             password: {passwd}
                             chpasswd: {{expire: False}}
                             ssh_pwauth: True
                             disable_root: 0
                             runcmd:
                             - chmod +x {py_script}
                             - python {py_script}
                             - echo {gateway}{gw_ip} >> /etc/sysconfig/network
                             - systemctl restart network
                             '''.format(gateway='GATEWAY=',
                                        gw_ip=gw_ip,
                                        user=self.instance_user,
                                        py_script=('/var/lib/cloud/scripts/'
                                                   'per-boot/'
                                                   'custom_net_config.py'),
                                        passwd=self.instance_pass)
        if (self.test_instance_repo and 'name' in
                self.test_instance_repo and not self.user_data):
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

        if install_packages is not None and not self.user_data:
            header = '''
                 packages:'''
            body = ''
            for package in install_packages.split(','):
                body += '''
                 - {package}'''.format(package=package)
            package = "".join((header, body))
            self.user_data = "".join((self.user_data, package))

        user_data = textwrap.dedent(self.user_data).lstrip().encode('utf8')
        user_data_b64 = base64.b64encode(user_data)
        return user_data_b64

    def _set_security_groups(self):
        """Security group creation

        This method create security group except network marked with security
        groups == false in test_networks
        """
        """
        Create security groups [icmp,ssh] for Deployed Guest Image
        """
        security_group = None
        mgmt_net = self.test_network_dict['public']
        if not ('sec_groups' in self.test_network_dict[mgmt_net] and
                not self.test_network_dict[mgmt_net]['sec_groups']):
            security_group = self._create_security_group()
            security_group = [{'name': security_group['name'],
                               'id': security_group['id']}]
        return security_group

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
        cmd = ("sudo ip netns exec qdhcp-" + network_id +
               " ping -c 10 " + ping_to_ip)
        ctrl_ip = urlparse(CONF.identity.uri).netloc.split(':')[0]
        result = self._run_command_over_ssh(ctrl_ip, cmd)
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
            if not srv.viewkeys() >= {'name', 'id', 'fip'}:
                raise ValueError('The yaml file missing of the following keys:'
                                 ' name, id or fip.')
