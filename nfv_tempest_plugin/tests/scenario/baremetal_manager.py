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

from __future__ import division  # Use Python3 divison in Python2

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

from math import ceil
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
        self.nfv_scripts_path = CONF.nfv_plugin_options.transfer_files_dest
        self.flavor_ref = CONF.compute.flavor_ref
        self.test_all_provider_networks = \
            CONF.nfv_plugin_options.test_all_provider_networks
        self.cpuregex = re.compile('^[0-9]{1,2}$')
        self.external_config = None
        self.test_setup_dict = {}
        self.remote_ssh_sec_groups = []
        self.remote_ssh_sec_groups_names = []
        self.qos_policy_groups = []
        self.servers = []
        self.test_network_dict = {}
        self.test_flavor_dict = {}
        self.test_instance_repo = {}
        self.user_data = {}
        self.user_data_b64 = ''
        self.fip = True
        self.external_resources_data = None

    @classmethod
    def setup_clients(cls):
        super(BareMetalManager, cls).setup_clients()
        cls.hypervisor_client = cls.manager.hypervisor_client
        cls.aggregates_client = cls.manager.aggregates_client
        cls.volumes_client = cls.os_primary.volumes_client_latest
        """
        security groups client
        floating ip client to support
        nova microversion>=2.36 changes
        """
        cls.security_groups_client = (
            cls.os_primary.security_groups_client)
        cls.security_group_rules_client = (
            cls.os_primary.security_group_rules_client)
        cls.floating_ips_client = (
            cls.os_primary.floating_ips_client)

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
            self.external_config = yaml.safe_load(f)

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

    def create_volume(self, **volume_args):
        """The method creates volume based on the args passed to the method.

        In case method call with empty parameters, default values will
        be used and default volume will be created.

        :param volume_args: Dict of parameters for the volume that should be
        created
        :return volume_id: ID of the created volume.
        """
        if 'name' not in volume_args:
            volume_args['name'] = data_utils.rand_name('volume')
        if 'size' not in volume_args:
            volume_args['size'] = CONF.volume.volume_size
        volume = self.volumes_client.create_volume(**volume_args)['volume']
        self.addClassResourceCleanup(
            self.volumes_client.wait_for_resource_deletion, volume['id'])
        self.addClassResourceCleanup(test_utils.call_and_ignore_notfound_exc,
                                     self.volumes_client.delete_volume,
                                     volume['id'])
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'available')
        return volume

    def _detach_volume(self, server, volume):
        """Detaches a volume and ignores if not found or not in-use

        param server: Created server details
        param volume: Created volume details
        """
        try:
            volume = self.volumes_client.show_volume(volume['id'])['volume']
            if volume['status'] == 'in-use':
                self.servers_client.detach_volume(server['id'], volume['id'])
        except lib_exc.NotFound:
            pass

    def attach_volume(self, server, volume):
        """Attaches volume to server

        param server: Created server details
        param volume: Created volume details
        :return volume_attachment: Volume attachment information.
        """
        attach_args = dict(volumeId=volume['id'])
        attachment = self.servers_client.attach_volume(
            server['id'], **attach_args)['volumeAttachment']
        self.addCleanup(waiters.wait_for_volume_resource_status,
                        self.volumes_client, volume['id'], 'available')
        self.addCleanup(self._detach_volume, server, volume)
        waiters.wait_for_volume_resource_status(self.volumes_client,
                                                volume['id'], 'in-use')
        return attachment

    def _get_dumpxml_instance_data(self, server, hypervisor):
        """Get dumpxml data from the instance

        :param server: Server name
        :param hypervisor: Hypervisor that hold the instance

        :return dumpxml_string
        """

        server_details = \
            self.os_admin.servers_client.show_server(server['id'])['server']
        # Check OSP release from hypervisor node
        osp_release = self._run_command_over_ssh(hypervisor,
                                                 'cat /etc/rhosp-release')
        # If OSP version is 16, use podman container to retrieve instance XML
        if '16' in osp_release:
            cmd = ('sudo podman exec -it nova_libvirt virsh -c '
                   'qemu:///system dumpxml {}')
        else:
            cmd = 'sudo virsh -c qemu:///system dumpxml {}'
        get_dumpxml = \
            cmd.format(server_details['OS-EXT-SRV-ATTR:instance_name'])
        dumpxml_data = self._run_command_over_ssh(hypervisor, get_dumpxml)
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
        vcpu_list = [int(vcpu.get('cpuset'))
                     for vcpu in vcpupin if vcpu is not None]
        return vcpu_list

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
        hyper_vcpu_list = self._run_command_over_ssh(hypervisor, cmd).split()
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
        numa_phys_content = self._retrieve_content_from_hiera(node=node,
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
            self._run_command_over_ssh(node, ovs_cmd).strip('\n').split('\n')
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
        dedicated, shared = self._retrieve_content_from_hiera(node=node,
                                                              keys=keys)
        dedicated = dedicated.strip('[""]')
        dedicated = self.parse_int_ranges_from_number_string(dedicated)
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

    def parse_int_ranges_from_number_string(self, input_string):
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
        # Construct a list of integers of instance emulatorpin threads
        parsed_instance_emulatorpin = \
            self.parse_int_ranges_from_number_string(instance_emulatorpin)

        # Construct a list of integers of nova emulator pin threads
        parsed_nova_emulatorpin = \
            self.parse_int_ranges_from_number_string(nova_emulatorpin)

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

    def create_and_set_availability_zone(self, zone_name=None, **kwargs):
        """Create availability zone with aggregation

        The method creates an aggregate and add the availability zone label
        :param zone_name: Availability zone name
        :param kwargs:
                aggr_name: The name of the aggregation to be created
                hyper_hosts: The list of the hypervisors to be attached
                aggr_meta: The metadata for the aggregation
        """
        if not zone_name:
            zone_name = data_utils.rand_name('availability-zone')
        aggr = self.create_and_set_aggregate(**kwargs)
        zone = self.aggregates_client.update_aggregate(
            aggregate_id=aggr['id'], availability_zone=zone_name)
        return zone['aggregate']

    def create_and_set_aggregate(self, hyper_hosts, aggr_name=None,
                                 aggr_meta=None):
        """Create aggregation and add an hypervisor to it

        :param hyper_hosts: The list of the hypervisors to be attached
        :param aggr_name: The name of the aggregation to be created
        :param aggr_meta: The metadata for the aggregation (optional)
        """
        if not aggr_name:
            aggr_name = data_utils.rand_name('aggregate')
        hyper_list = []
        for hyper in self.hypervisor_client.list_hypervisors()['hypervisors']:
            for host in hyper_hosts:
                if hyper['hypervisor_hostname'].split('.')[0] in host:
                    hyper_list.append(hyper['hypervisor_hostname'])
        if not hyper_list:
            raise ValueError('Provided host for the aggregate does not exist.')

        aggr = self.aggregates_client.create_aggregate(name=aggr_name)
        self.addCleanup(self.aggregates_client.delete_aggregate,
                        aggr['aggregate']['id'])
        if aggr_meta:
            meta_body = {aggr_meta.split('=')[0]: aggr_meta.split('=')[1]}
            self.aggregates_client.set_metadata(aggr['aggregate']['id'],
                                                metadata=meta_body)
        for host in hyper_list:
            self.aggregates_client.add_host(aggr['aggregate']['id'], host=host)
            self.addCleanup(self.aggregates_client.remove_host,
                            aggr['aggregate']['id'], host=host)
        return aggr['aggregate']

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
            host_name = re.split(r"\.", host[0])[0]
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
            if ('tag' in net and (2.32 <= float(self.request_microversion)
                                  <= 2.36 or float(self.request_microversion)
                                  >= 2.42)):
                self.test_network_dict[net['name']]['tag'] = net['tag']
            if 'trusted_vf' in net and net['trusted_vf']:
                self.test_network_dict[net['name']]['trusted_vf'] = True
            if 'switchdev' in net and net['switchdev']:
                self.test_network_dict[net['name']]['switchdev'] = True
            if 'min_qos' in net and net['min_qos']:
                self.test_network_dict[net['name']]['min_qos'] = \
                    net['min_qos']
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
                    (net_param['provider:network_type'] == 'vlan'
                     or net_param['provider:network_type'] == 'flat'):
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
               set_qos: true/false set qos policy during port creation

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
                                    'namestart': 'port-smoke',
                                    'binding:profile': {}}
                if 'port_type' in net_param:
                    create_port_body['binding:vnic_type'] = \
                        net_param['port_type']
                    if self.remote_ssh_sec_groups and net_name == \
                            self.test_network_dict['public']:
                        create_port_body['security_groups'] = \
                            [s['id'] for s in self.remote_ssh_sec_groups]
                    if 'trusted_vf' in net_param and \
                       net_param['trusted_vf'] and \
                       net_param['port_type'] == 'direct':
                        create_port_body['binding:profile']['trusted'] = True
                    if 'switchdev' in net_param and \
                       net_param['switchdev'] and \
                       net_param['port_type'] == 'direct':
                        create_port_body['binding:profile']['capabilities'] = \
                            ['switchdev']

                    if len(create_port_body['binding:profile']) == 0:
                        del create_port_body['binding:profile']
                    port = self._create_port(network_id=net_param['net-id'],
                                             **create_port_body)
                    # No option to create port with QoS, due to neutron API
                    # Using update port
                    if 'min_qos' in net_param and \
                        net_param['min_qos'] and \
                        net_param['port_type'] == 'direct' and \
                        'set_qos' in kwargs:
                        port_name = data_utils.rand_name('port-min-qos')
                        port_args = {'name': port_name}
                        if kwargs['set_qos']:
                            port_args['qos_policy_id'] = \
                                self.qos_policy_groups['id']
                        self.update_port(port['id'], **port_args)
                    net_var = {'uuid': net_param['net-id'], 'port': port['id']}
                    if 'tag' in net_param:
                        net_var['tag'] = net_param['tag']
                    networks_list.append(net_var) \
                        if net_name != self.test_network_dict['public'] else \
                        networks_list.insert(0, net_var)
            ports_list.append(networks_list)
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

    def create_network_qos_policy(self, namestart='qos-policy'):
        """Creates a network QoS policy"""
        qos_client = self.os_admin.qos_client
        result = qos_client.create_qos_policy(
            name=data_utils.rand_name(namestart))
        self.assertIsNotNone(result, 'Unable to create policy')
        qos_policy = result['policy']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        qos_client.delete_qos_policy,
                        qos_policy['id'])
        return qos_policy

    def create_min_bw_qos_rule(self, policy_id=None, min_kbps=None,
                               direction='egress'):
        """Creates a minimum bandwidth QoS rule

        NOTE: Not all kernel versions support minimum bandwidth for all
        NIC drivers.

        Only egress (guest --> outside) traffic is currently supported.

        :param policy_id
        :param min_kbps: Minimum kbps bandwidth to apply to rule
        :param direction: Traffic direction that the rule applies to
        """
        SUPPORTED_DIRECTIONS = 'egress'
        if not policy_id:
            policy_id = self.qos_policy_groups[0]['id']
        if direction not in SUPPORTED_DIRECTIONS:
            raise ValueError('{d} is not a supported direction, supported '
                             'directions: {s_p}'
                             .format(d=direction,
                                     s_p=SUPPORTED_DIRECTIONS.join(', ')))
        qos_min_bw_client = self.os_admin.qos_min_bw_client
        result = qos_min_bw_client.create_minimum_bandwidth_rule(
            policy_id, **{'min_kbps': min_kbps, 'direction': direction})
        self.assertIsNotNone(result, 'Unable to create minimum bandwidth '
                                     'QoS rule')
        qos_rule = result['minimum_bandwidth_rule']
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            qos_min_bw_client.delete_minimum_bandwidth_rule, policy_id,
            qos_rule['id'])

    def update_port(self, port_id, **kwargs):
        """update port

        The method, used to update port_body of port.
        kwargs patam should includ additional parameters to be set
        as per the following:
        https://docs.openstack.org/api-ref/network/v2/ \
                ?expanded=update-port-detail#update-port
        :param port_id
        :param kwargs
               qos_policy_id: id of policy to be attached to the port
        """
        ports_client = self.os_admin.ports_client
        ports_client.update_port(port_id, **kwargs)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            ports_client.update_port, port_id, qos_policy_id=None)

    def create_server(self, name=None, image_id=None, flavor=None,
                      validatable=False, srv_state=None,
                      wait_on_delete=True, clients=None, **kwargs):
        """This Method Overrides Manager::Createserver to support Gates needs

        :param validatable:
        :param clients:
        :param image_id:
        :param wait_on_delete:
        :param srv_state:
        :param flavor:
        :param name:
        """
        if 'key_name' not in kwargs:
            key_pair = self.create_keypair()
            kwargs['key_name'] = key_pair['name']

        net_id = []
        networks = []
        (CONF.compute_feature_enabled.config_drive
         and kwargs.update({'config_drive': True}))
        if 'networks' in kwargs:
            net_id = kwargs['networks']
            kwargs.pop('networks', None)
        else:
            networks = self.networks_client.list_networks(
                **{'router:external': False})['networks']

        for network in networks:
            net_id.append({'uuid': network['id']})

        server = super(BareMetalManager,
                       self).create_server(name=name,
                                           networks=net_id,
                                           image_id=image_id,
                                           flavor=flavor,
                                           wait_until=srv_state,
                                           **kwargs)
        self.servers.append(server)
        return server

    def create_server_with_fip(self, num_servers=1, use_mgmt_only=False,
                               fip=True, networks=None, srv_state='ACTIVE',
                               raise_on_error=True, **kwargs):
        """Create defined number of the instances with floating ip.

        :param num_servers: The number of servers to boot up.
        :param use_mgmt_only: Boot instances with mgmt net only.
        :param fip: Creation of the floating ip for the server.
        :param networks: List of networks/ports for the servers.
        :param srv_state: The state of the server to expect.
        :param raise_on_error: Raise as error on failed build of the server.
        :param kwargs:
                srv_details: Provide per server override options.
                             Supported options:
                                - flavor (flavor id)
                                - image (image id)
                             For example:
                             srv_details = {0: {'flavor': <flavor_id>},
                                            1: {'flavor': <flavor_id>,
                                                'image': <image_id>}}

        :return: List of created servers
        """
        servers = []
        port = {}

        if not any(isinstance(el, list) for el in networks):
            raise ValueError('Network expect to be as a list of lists')

        override_details = None
        if kwargs.get('srv_details'):
            override_details = kwargs.pop('srv_details')

        for num in range(num_servers):
            kwargs['networks'] = networks[num]

            if override_details:
                if 'flavor' in override_details[num]:
                    kwargs['flavor'] = override_details[num]['flavor']
                if 'image' in override_details[num]:
                    kwargs['image_id'] = override_details[num]['image']
                if 'srv_state' in override_details[num]:
                    kwargs['srv_state'] = override_details[num]['srv_state']

            """ If this parameters exist, parse only mgmt network.
            Example live migration can't run with SRIOV ports attached"""
            if use_mgmt_only:
                del (kwargs['networks'][1:])

            LOG.info('Create instance - {}'.format(num + 1))
            servers.append(self.create_server(**kwargs))
        for num, server in enumerate(servers):
            waiters.wait_for_server_status(self.os_admin.servers_client,
                                           server['id'], srv_state,
                                           raise_on_error=raise_on_error)
            LOG.info('The instance - {} is in an {} state'.format(num + 1,
                     srv_state))
            if srv_state == 'ACTIVE':
                port = self.os_admin.ports_client.list_ports(device_id=server[
                    'id'], network_id=networks[num][0]['uuid'])['ports'][0]
            if fip and srv_state == 'ACTIVE':
                server['fip'] = \
                    self.create_floating_ip(server,
                                            port['id'],
                                            self.public_network)[
                        'floating_ip_address']
                LOG.info('The {} fip is allocated to the instance'.format(
                    server['fip']))
            elif srv_state == 'ACTIVE':
                server['fip'] = port['fixed_ips'][0]['ip_address']
                server['network_id'] = networks[num][0]['uuid']
                LOG.info('The {} fixed ip set for the instance'.format(
                    server['fip']))
        return servers

    def create_server_with_resources(self, num_servers=1, num_ports=None,
                                     test=None, **kwargs):
        """The method creates resources and call for the servers method

        The following resources are created:
        - Aggregation
        - Flavor creation / verification
        - Key pair
        - Security groups
        - Test networks
        - Networks ports
        - Cloud init preparation
        - Servers creation
        - Floating ip attachment to the servers
        - QoS attachments to port

        :param num_servers: The number of servers to boot up.
        :param num_ports: The number of ports to the created.
                          Default to (num_servers)
        :param test: Currently executed test. Provide test specific parameters.
        :param kwargs:
                set_qos: true/false create port with qos_policy
                availability_zone: Create and set availability zone
                    zone_name: Name of availability zone (optional)
                    aggr_name: Name of aggregate (optional)
                    hyper_hosts: The list of the hypervisors to be attached
                    aggr_meta: Metadata for aggregate (optional)

                    Example: {'availability_zone': {'hyper_hosts': 'compute0'}}

        :return servers, key_pair
        """
        LOG.info('Creating resources...')

        if num_ports is None:
            num_ports = num_servers

        # Check for the test config file
        self.assertTrue(test in self.test_setup_dict,
                        'The test requires {0} config in external_config_file'.
                        format(test))

        # In case resources created externally, set them.
        if self.external_resources_data is not None:
            servers, key_pair = self._organize_external_created_resources(test)
            LOG.info('The resources created by the external tool. '
                     'Continue to the test.')
            return servers, key_pair

        # Create and configure availability zone
        if kwargs.get('availability_zone'):
            avail_zone = kwargs.pop('availability_zone')
            kwargs['availability_zone'] = \
                self.create_and_set_availability_zone(
                    **avail_zone)['availability_zone']

        # Create and configure aggregation zone if specified
        if self.test_setup_dict[test]['aggregate'] is not None:
            aggr_hosts = self.test_setup_dict[test]['aggregate']['hosts']
            aggr_meta = self.test_setup_dict[test]['aggregate']['metadata']
            self.create_and_set_aggregate(test, aggr_hosts, aggr_meta)

        # Flavor creation
        if not kwargs.get('flavor'):
            flavor_check = self.check_flavor_existence(test)
            if flavor_check is False:
                flavor_name = self.test_setup_dict[test]['flavor']
                LOG.info('Flavor {} not found. Creating.'.format(flavor_name))
                try:
                    self.flavor_ref = self.create_flavor(
                        **self.test_flavor_dict[flavor_name])
                except KeyError as exc:
                    err_msg = "Unable to locate {} flavor details for " \
                              "the creation".format(exc)
                    raise Exception(err_msg)

            kwargs['flavor'] = self.flavor_ref

        LOG.info('Creating networks, keypair, security groups, router and '
                 'prepare cloud init.')
        # Key pair creation
        key_pair = self.create_keypair()
        kwargs['key_name'] = key_pair['name']

        # Network, subnet, router and security group creation
        self._create_test_networks()
        self._set_remote_ssh_sec_groups()
        if self.remote_ssh_sec_groups_names:
            kwargs['security_groups'] = self.remote_ssh_sec_groups_names
        ports_list = \
            self._create_ports_on_networks(num_ports=num_ports,
                                           **kwargs)
        # After port creation remove kwargs['set_qos']
        if 'set_qos' in kwargs:
            kwargs.pop('set_qos')
        router_exist = True
        if 'router' in self.test_setup_dict[test]:
            router_exist = self.test_setup_dict[test]['router']
        if router_exist:
            self._add_subnet_to_router()
        # Prepare cloudinit
        packages = None
        if 'package-names' in self.test_setup_dict[test].keys():
            packages = self.test_setup_dict[test]['package-names']
        kwargs['user_data'] = self._prepare_cloudinit_file(packages)
        servers = []
        if num_servers:
            servers = self.create_server_with_fip(num_servers=num_servers,
                                                  networks=ports_list,
                                                  **kwargs)
        return servers, key_pair

    def _check_pid_ovs(self, ip_address):
        """This method checks if ovs pid exist

        param ip_address: server ip address
        return  ovs pid or Exception if it does not exist
        """

        ovs_process = "sudo pidof ovs-vswitchd"
        ovs_process_pid = (self._run_command_over_ssh(ip_address,
                                                      ovs_process)).strip('\n')
        if not ovs_process_pid:
            raise ValueError('The ovs-vswitchd process is missing.')
        return ovs_process_pid

    def _check_number_queues(self):
        """This method checks the number of max queues"""
        self.ip_address = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc'})
        ovs_process_pid = self._check_pid_ovs(self.ip_address[0])
        count_pmd = "ps -T -p {} | grep pmd | wc -l".format(ovs_process_pid)
        numpmds = int(self._run_command_over_ssh(self.ip_address[0],
                                                 count_pmd))
        # We ensure that a number is being parsed, otherwise we fail
        cmd = r'sudo ovs-vsctl show | sed -n "s/.*n_rxq=.\([1-9]\).*/\\1/p"'
        numqueues = (self._run_command_over_ssh(self.ip_address[0],
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

    def _set_remote_ssh_sec_groups(self):
        """Security group creation

        This method create security group except network marked with security
        groups == false in test_networks
        """
        """
        Create security groups [icmp,ssh] for Deployed Guest Image
        """
        mgmt_net = self.test_network_dict['public']
        if not ('sec_groups' in self.test_network_dict[mgmt_net]
                and not self.test_network_dict[mgmt_net]['sec_groups']):
            security_group = self._create_security_group()
            self.remote_ssh_sec_groups_names = \
                [{'name': security_group['name']}]
            self.remote_ssh_sec_groups = [{'name': security_group['name'],
                                           'id': security_group['id']}]

    def _create_security_group(self):
        """Security group creation

        to conform changes in nova clients on microversions>=2.36
        Create security groups and call method create rules
        [icmp,ssh]
        """

        sg_name = data_utils.rand_name(self.__class__.__name__)
        sg_desc = sg_name + " description"
        client = self.security_groups_client
        secgroup = client.create_security_group(
            name=sg_name, description=sg_desc)['security_group']
        self.assertEqual(secgroup['name'], sg_name)
        self.assertEqual(secgroup['description'], sg_desc)
        self.addCleanup(
            test_utils.call_and_ignore_notfound_exc,
            self.security_groups_client.delete_security_group,
            secgroup['id'])

        # Add rules to the security group
        self._create_loginable_secgroup_rule(secgroup['id'])

        return secgroup

    def _create_loginable_secgroup_rule(self, secgroup_id=None):
        """Add secgroups rules

        To conform changes in nova clients on microversions>=2.36
        This method add sg rules with neutron client
        This method find default security group or specific one
        and add icmp and ssh rules
        """
        rule_list = \
            jsonutils.loads(CONF.nfv_plugin_options.login_security_group_rules)
        client = self.security_groups_client
        client_rules = self.security_group_rules_client
        if not secgroup_id:
            sgs = client.list_security_group['security_groups']
            for sg in sgs:
                if sg['name'] == 'default':
                    secgroup_id = sg['id']
                    break

        for rule in rule_list:
            direction = rule.pop('direction')
            client_rules.create_security_group_rule(
                direction=direction,
                security_group_id=secgroup_id,
                **rule)

    def create_floating_ip(self, server, mgmt_port_id, public_network_id):
        """Create floating ip to server

        To conform changes in nova clients on microversions>=2.36
        This method create fip with neutron client
        """
        fip_client = self.floating_ips_client
        floating_ip_args = {
            'floating_network_id': public_network_id,
            'port_id': mgmt_port_id,
            'tenant_id': server['tenant_id']
        }
        floating_ip = \
            fip_client.create_floatingip(**floating_ip_args)['floatingip']
        self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                        fip_client.delete_floatingip,
                        floating_ip['id'])
        return floating_ip

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
            statistics[interface] = yaml.safe_load(self._run_command_over_ssh(
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

    def check_instance_connectivity(self, ip_addr, user, key_pair):
        """Check connectivity state of the instance

        The function will test the following protocols: ICMP, SSH

        :param ip_addr: The address of the instance
        :param user: Connection user
        :param key_pair: SSH key for the instance connection
        """
        msg = 'Timed out waiting for {} to become reachable'.format(ip_addr)
        self.assertTrue(self.ping_ip_address(ip_addr), msg)
        self.assertTrue(self.get_remote_client(ip_addr, user, key_pair), msg)

    def check_guest_interface_config(self, ssh_client, provider_networks,
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
            self.assertNotEmpty(guest_interface, msg.format(h=hostname,
                                                            m=mac))
            LOG.info("Located '{m}' in guest '{h}' on interface '{g}'".format(
                m=mac, h=hostname, g=guest_interface))
            # Attempt to discover guest interface using an IP address
            ip_interface = ssh_client.get_nic_name_by_ip(ip)
            msg = ("Guest '{h}' exepected to have interface '{g}' to be "
                   "configured with IP address '{i}'")
            self.assertNotEmpty(ip_interface, msg.format(h=hostname,
                                                         g=guest_interface,
                                                         i=ip))
            LOG.info("Guest '{h}' has interface '{g}' configured with "
                     "IP address '{i}".format(h=hostname, g=guest_interface,
                                              i=ip))

    def check_guest_provider_networks(self, servers, key_pair):
        """Check guest provider networks

        This function tests ICMP traffic on all provider networks
        between multiple servers.

        :param servers: List of servers to verify
        :param key-pair: Key pair used to authenticate with server
        """
        # In the current itteration, if only a single server is spawned
        # no pings will be performed.
        # TODO(vkhitrin): In the future, consider pinging default gateway
        if len(servers) == 1:
            LOG.info('Only one server was spawned, no neigbors to ping')
            return True

        for server in servers:
            # Copy servers list to a helper variable
            neighbor_servers = servers[:]
            # Initialize a list of neighbors IPs
            neighbors_ips = []
            # Remove current server from potential server neigbors list
            neighbor_servers.remove(server)
            # Retrieve neighbors IPs from their provier networks
            for neighbor_server in neighbor_servers:
                # Iterate over provider networks for current server and
                # neighbor servers and append potential IP to ping only if
                # both the neighbor and current server are attached to
                # same network
                # Currently it is inefficient to loop this way, consider
                # improving itteration logic
                for neighbor_network in neighbor_server['provider_networks']:
                    for server_network in server['provider_networks']:
                        if neighbor_network['network_id'] == \
                            server_network['network_id']:
                            neighbors_ips.append(
                                neighbor_network['ip_address'])

            ssh_client = self.get_remote_client(server['fip'],
                                                self.instance_user,
                                                key_pair['private_key'])

            hostname = server['name']
            for neighbors_ip in neighbors_ips:
                LOG.info("Guest '{h}' will attempt to "
                         "ping {i}".format(h=hostname, i=neighbors_ip))
                try:
                    ssh_client.icmp_check(neighbors_ip)
                except lib_exc.SSHExecCommandFailed:
                    msg = ("Guest '{h}' failed to ping "
                           "IP '{i}'".format(h=hostname, i=neighbors_ip))
                    raise AssertionError(msg)

                LOG.info("Guest '{h}' successfully was able to ping "
                         "IP '{i}'".format(h=hostname, i=neighbors_ip))

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
        output = list(filter(None, self._run_command_over_ssh(
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

    def get_ovs_port_names(self, servers):
        """This method get ovs port names for each server

        for each server, this method will add mgmt_port and other_port
        values
        :param servers: server list
        return list of ports of each hypervisor
        """
        # get the ports name used for sending/reciving multicast traffic
        # it will be a different port than the management one that will be
        # connected to a switch in which igmp snooping is configured
        port_list = {}
        management_ips = []
        floating_ips = (self.os_admin.floating_ips_client.list_floatingips()
                        ['floatingips'])
        for floating_ip in floating_ips:
            management_ips.append(floating_ip['fixed_ip_address'])
        for server in servers:
            if server['hypervisor_ip'] not in port_list.keys():
                port_list[server['hypervisor_ip']] = []
            ports = self.os_admin.ports_client.list_ports(
                device_id=server['id'])['ports']
            for port in ports:
                ovs_port_name = (port['binding:vif_details']
                                 ['vhostuser_socket'].split('/')[-1])
                if port['fixed_ips'][0]['ip_address'] not in management_ips:
                    server['other_port'] = ovs_port_name
                else:
                    server['mgmt_port'] = ovs_port_name
                port_list[server['hypervisor_ip']].append(ovs_port_name)
        return port_list

    def list_available_resources_on_hypervisor(self, hypervisor):
        """List available CPU and RAM on dedicated hypervisor"""
        hyp_list = self.os_admin.hypervisor_client.list_hypervisors()[
            'hypervisors']
        if not any(hypervisor in a['hypervisor_hostname'] for a in hyp_list):
            raise ValueError('Specifyed hypervisor has not been found.')

        hyper_id = self.os_admin.hypervisor_client.search_hypervisor(
            hypervisor)['hypervisors'][0]['id']
        hyper_info = self.os_admin.hypervisor_client.show_hypervisor(
            hyper_id)['hypervisor']
        cpu_total = hyper_info['vcpus']
        cpu_used = hyper_info['vcpus_used']
        cpu_free = hyper_info['vcpus'] - hyper_info['vcpus_used']
        cpu_free_per_numa = hyper_info['vcpus'] // 2 - hyper_info['vcpus_used']
        ram_free = hyper_info['free_ram_mb'] // 1024
        return {'cpu_total': cpu_total, 'cpu_used': cpu_used,
                'cpu_free_per_numa': cpu_free_per_numa, 'cpu_free': cpu_free,
                'ram_free': ram_free}

    def _get_controllers_ip_from_undercloud(self, **kwargs):
        """This method returns the list of controllers ip

        :param kwargs['shell']
        """
        command = 'openstack server list -c \'Name\' -c ' \
                  '\'Networks\' -f value | grep -i {0} | ' \
                  'cut -d\"=\" -f2'.format('controller')
        ip_address_list = self._run_local_cmd_shell_with_venv(
            command, kwargs['shell'])
        return ip_address_list

    def get_interfaces_from_overcloud_node(self, node_ip):
        """Retrieve interfaces from overcloud node

        :param node_ip
        """
        cmd = 'sudo ip link show'
        output = self._run_command_over_ssh(node_ip, cmd)
        return output

    def check_qos_attached_to_guest(self, server, min_bw=False):
        """Check QoS attachment to guest

        This method checks if QoS is applied to an interface on hypervisor
        that is attached to guest

        :param server
        :param min_bw: Check for minimum bandwidth QoS
        """
        # Initialize parameters
        found_qos = False
        interface_data = self.get_interfaces_from_overcloud_node(
            server['hypervisor_ip'])
        ports_client = self.os_admin.ports_client
        ports = ports_client.list_ports(device_id=server['id'])
        # Iterate over ports
        for port in ports['ports']:
            # If port has a QoS policy
            if port['qos_policy_id']:
                found_qos = True
                # Construct regular expression to locate port's MAC address
                re_string = r'.*{}.*'.format(port['mac_address'])
                line = re.search(re_string, interface_data)
                # Failed to locate MAC address on hypervisor
                if not line:
                    raise ValueError("Failed to locate interface with MAC "
                                     "'{}' on hypervisor"
                                     .format(port['mac_address']))
                line = line.group(0)
                # Check minimum bandwidth QoS
                if min_bw:
                    qos_min_bw_client = self.os_admin.qos_min_bw_client
                    min_qos_rule = \
                        qos_min_bw_client.list_minimum_bandwidth_rules(
                            port['qos_policy_id'])['minimum_bandwidth_rules']
                    # OpenStack API displays the size in Kbps
                    min_kbps = min_qos_rule[0]['min_kbps']
                    # Construct string to match Linux operating system
                    min_mbps = str(int(ceil(min_kbps / 1000)))
                    min_mbps = '{}Mbps'.format(min_mbps)
                    # Linux operating system displays the size in Mbps
                    qos = re.search(r'min_tx_rate \w+', line)
                    # Failed to locate min QoS
                    if not qos:
                        raise ValueError("Failed to dicover min QoS for "
                                         "interface with MAC '{}'"
                                         .format(port['mac_address']))
                    qos = qos.group(0)
                    # Filter QoS number
                    qos = qos.replace('min_tx_rate ', '')
                    self.assertEqual(min_mbps, qos)
        if not found_qos:
            raise ValueError('No QoS policies were applied to ports')
