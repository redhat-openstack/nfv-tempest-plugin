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
import os.path
import paramiko
import re
import textwrap
import time
import xml.etree.ElementTree as ELEMENTTree
import yaml


from nfv_tempest_plugin.services.os_clients import OsClients
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from oslo_config import cfg
from oslo_log import log
from oslo_serialization import jsonutils
from swiftclient.service import SwiftError
from tempest import config
from tempest.lib import exceptions as lib_exc
"""Python 2 and 3 support"""
from six.moves import StringIO
from six.moves.urllib.parse import urlparse

CONF = config.CONF
LOG = log.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class ManagerMixin(object):
    def read_terraform_state_in_swift(self, swift_container='terraform',
                                      swift_object='tfstate.tf'):
        """This method reads from tfstate.tf and populates CONF object

        cloud here is overcloud and swift container is terraform
        tfstate is stored by default in this location
        NOTE: The swift backend is deprecated starting from terraform 1.3.0
        """
        try:
            os_client = OsClients()
            sc = os_client.overcloud_swift_client
            object_content = sc.get_object(swift_container, swift_object)[1]
            data = json.loads(object_content.decode('utf-8'))
        except SwiftError as error:
            LOG.error(f'Swift error occurred {error.value}: \
                    while retrieving swift object \
                    {swift_container}->{swift_object}')
            raise
        except AttributeError as error:
            LOG.error(f"AttributeError {error} --> object_content: \
                      {object_content} type: {type(object_content)}")
            raise

        # lets populate the Network, Flavor and Image sections from here
        # Directly into CONF -
        # CONF.network.public_network_id
        filters = ['subnet_v2', 'network_v2', 'router_v2', 'flavor_v2']
        for i in data['resources']:
            for f in filters:
                if f in i['type']:
                    for j in i['instances']:
                        if 'network' in f:
                            # networkdata
                            LOG.info(f"Network Record retrieived {j}")
                            if j['attributes']['name'] == \
                                    CONF.network.floating_network_name:
                                CONF.network.public_network_id = \
                                    j['attributes']['id']
                        elif 'flavor' in f:
                            # flavordata
                            # However, we are only storing
                            # CONF.compute.flavor_ref
                            # which is hardcoded to 100
                            LOG.info(f"flavor Record retrieved {j}")
                            if j['attributes']['id'] == \
                                    CONF.compute.flavor_ref:
                                continue
                                # skipping since this is hard coded.
                            CONF.compute.flavor_ref_alt = \
                                j['attributes']['id']
                        elif 'router' in f:
                            continue
                            # routerdata
                            # this is being discovered so populating
                            # this is not going to help.

    def read_external_config_file(self):
        """This Method reads network_config.yml

        Reads config data and assign it to dictionaries
        """
        with open(CONF.nfv_plugin_options.external_config_file, 'r') as f:
            self.external_config = yaml.safe_load(f)

        if not CONF.nfv_plugin_options.external_resources_output_file:
            """Hold flavor, net and images lists"""
            # TODO(read and parse to util move to util)
            # Adding routine to load CONF from tfstate.tf
            if CONF.nfv_plugin_options.terraform_swift_integration:
                self.read_terraform_state_in_swift()
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

        if self.external_config.get('tests-setup'):
            for test in self.external_config['tests-setup']:
                self.test_setup_dict[test['name']] = {}
                self.test_setup_dict[test['name']]['config_dict'] = {}
                if 'flavor' in test and test['flavor'] is not None:
                    self.test_setup_dict[test['name']]['flavor'] = \
                        test['flavor']
                if 'image' in test and test['image'] is not None:
                    self.test_setup_dict[test['name']]['image'] = \
                        test['image']
                if 'bonding_config' in test and \
                        test['bonding_config'] is not None:
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

                if 'data_network' in test and test['data_network'] is not None:
                    self.test_setup_dict[test['name']]['data_network'] = \
                        test['data_network']

        if not CONF.nfv_plugin_options.external_resources_output_file:
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
        cmd = 'sudo virsh -c qemu:///system dumpxml'
        cmd += ' {}'
        get_dumpxml = \
            cmd.format(server_details['OS-EXT-SRV-ATTR:instance_name'])
        dumpxml_data = shell_utils.\
            run_command_over_ssh(hypervisor, get_dumpxml)
        dumpxml_data = '\r'.join(list(dumpxml_data.split('\r')))
        dumpxml_string = ELEMENTTree.fromstring(dumpxml_data)

        return dumpxml_string

    def get_container_cli(self, container_cli_must=True, hypervisor=None):
        """Search for openstack version and return container cli

        :parm container_cli_must: indication cli below Train container
        :return container_cli: None or container cli name
        """
        container_cli = None
        rhosp_release = self.get_osp_release(hypervisor)
        if rhosp_release >= 16:
            container_cli = 'podman'
        elif container_cli_must:
            container_cli = 'docker'
        return container_cli

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
        vcpu_total_list = list()
        for vcpu in vcpu_list:
            split_list = vcpu.split(',')
            for cpu in split_list:
                if '-' in cpu:
                    splited_cpu = cpu.split('-')
                    cpus = list(range(int(splited_cpu[0]),
                                      int(splited_cpu[1]) + 1))
                    vcpu_total_list.extend(cpus)
                else:
                    vcpu_total_list.append(cpu)
        if vcpu_total_list:
            vcpu_list = vcpu_total_list
        vcpu_final_list = [int(vcpu) for vcpu in vcpu_list]
        return list(set(vcpu_final_list))

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
        hyper_vcpu_list = shell_utils.\
            run_command_over_ssh(hypervisor, cmd).split()
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

    def locate_dedicated_and_shared_cpu_set(self, node=None):
        """Locate dedicated and shared cpu set

        The method locates the cpus provided by the compute for the instances.
        The cpus divided into two groups: dedicated and shared

        :param node: The node that the query should executed on.
        :return Two lists of dedicated and shared cpus set
        """
        if not node:
            node = self._get_hypervisor_ip_from_undercloud()[0]
        dedicated_cpus = "cpu_dedicated_set"
        shared_cpus = "cpu_shared_set"
        config_path = "/var/lib/openstack/config/nova" \
                      "/04-cpu-pinning-nova.conf"
        section = "compute"

        dedicated = shell_utils.\
            get_value_from_ini_config(node,
                                      config_path,
                                      section,
                                      dedicated_cpus)
        shared = shell_utils.\
            get_value_from_ini_config(node,
                                      config_path,
                                      section,
                                      shared_cpus)
        dedicated = shell_utils.parse_int_ranges_from_number_string(dedicated)
        shared = shell_utils.parse_int_ranges_from_number_string(shared)
        return dedicated, shared

    def locate_numa_aware_networks(self, numa_physnets):
        """Locate numa aware networks

        :param numa_physnets: Dict of numa aware and non aware physnets
        :return numa_aware_net aware and non aware dict
        """
        numa_aware_net = self.networks_client.list_networks(
            **{'provider:physical_network':
                numa_physnets['numa_aware_net']['net'],
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
        nova_emulatorpin = shell_utils.\
            get_value_from_ini_config(overcloud_node,
                                      config_path,
                                      check_section,
                                      check_value)
        # Construct a list of integers of instance emulatorpin threads
        parsed_instance_emulatorpin = shell_utils.\
            parse_int_ranges_from_number_string(instance_emulatorpin)

        # Construct a list of integers of nova emulator pin threads
        parsed_nova_emulatorpin = shell_utils.\
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
        nova_rx_tx = shell_utils.\
            get_value_from_ini_config(overcloud_node,
                                      config_path,
                                      check_section,
                                      check_value)

        if instance_rx_tx == nova_rx_tx:
            return True
        return False

    def check_number_queues(self):
        """This method checks the number of max queues"""
        self.ip_address = self._get_hypervisor_ip_from_undercloud()
        ovs_process_pid = shell_utils.check_pid_ovs(self.ip_address[0])
        count_pmd = "ps -T -p {} | grep pmd | wc -l".format(ovs_process_pid)
        numpmds = int(shell_utils.run_command_over_ssh(self.ip_address[0],
                                                       count_pmd))
        # We ensure that a number is being parsed, otherwise we fail
        cmd = r'sudo ovs-vsctl show | sed -n "s/.*n_rxq=.\([1-9]\).*/\\1/p"'
        numqueues = (shell_utils.
                     run_command_over_ssh(self.ip_address[0],
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
        repos_config = CONF.nfv_plugin_options.instance_repo
        repos = ''
        if len(repos_config.items()) > 0:
            repos = '''
                             yum_repos:
                    '''
        for repo_name, repo_url in iter(repos_config.items()):
            repos += '''
                                 {repo_name}:
                                     name: {repo_name}
                                     baseurl: {repo_url}
                                     enabled: true
                                     gpgcheck: false
                    '''.format(repo_name=repo_name,
                               repo_url=repo_url)
        self.user_data = "".join((self.user_data, repos))

        packages = []
        if install_packages is not None:
            packages += install_packages
        try:
            packages += CONF.nfv_plugin_options.install_packages
        except cfg.NoSuchOptError:
            pass
        if len(packages) > 0:
            packages = list(set(packages))
            header = '''
                             packages:'''
            body = ''
            for package in packages:
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
        key_type = None
        for val in ["rsa", "ecdsa"]:
            try:
                if val == "ecdsa":
                    ssh_key = paramiko.ECDSAKey.from_private_key(
                        StringIO(ssh_key))
                else:
                    ssh_key = paramiko.RSAKey.from_private_key(
                        StringIO(ssh_key))
                key_type = val
                break
            except paramiko.ssh_exception.SSHException:
                pass
        self.assertIsNotNone(key_type,
                             "Unknown key type, "
                             "only supported RSA and ECDSA")
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
        result = shell_utils.run_command_over_ssh(ctrl_ip, cmd)
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
            key_pair = {'private_key': key.read(),
                        'name': os.path.basename(
                            self.external_resources_data['key_pair'])
                        .split('.')[0]}
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
        self.ip_address = self._get_hypervisor_ip_from_undercloud()
        hypervisor_ip = self.ip_address[0]
        if hypervisor is not None:
            if hypervisor not in self.ip_address:
                raise ValueError('invalid hypervisor ip {}, not in {}'
                                 .format(hypervisor,
                                         ' '.join(self.ip_address)))
            else:
                hypervisor_ip = hypervisor

        shell_utils.check_pid_ovs(hypervisor_ip)
        # We ensure that a number is being parsed, otherwise we fail
        statistics = {}
        for interface in interfaces:
            command = 'sudo ovs-vsctl get Interface {} ' \
                      'statistics'.format(interface)
            statistics[interface] = \
                yaml.safe_load(
                    shell_utils.run_command_over_ssh(
                        hypervisor_ip, command).replace(
                        '"', '').replace(
                        '{', '{"').replace(', ', ', "').replace('=', '":'))
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
        self.ip_address = self._get_hypervisor_ip_from_undercloud()
        hypervisor_ip = self.ip_address[0]
        if hypervisor is not None:
            if hypervisor not in self.ip_address:
                raise ValueError('invalid hypervisor ip {}, not in {}'
                                 .format(hypervisor,
                                         ' '.join(self.ip_address)))
            else:
                hypervisor_ip = hypervisor

        shell_utils.check_pid_ovs(hypervisor_ip)

        command = 'sudo ovs-appctl mdb/show {}'.format(switch)
        output = list(filter(None,
                             shell_utils.run_command_over_ssh(
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

    def get_ovn_multicast_groups(self):
        """Retrieves OVN multicast groups from OVN southbound DB

        :return multicast groups
        """
        output_data = []
        multicast_ips = []
        controller = shell_utils.get_controllers_ip_from_undercloud(
            shell=CONF.nfv_plugin_options.undercloud_rc_file)[0]
        ovn_igmp_cmd = ('sudo podman exec -it ovn_controller'
                        ' ovn-sbctl --no-leader-only list igmp_group')
        ovn_igmp_output = shell_utils.run_command_over_ssh(
            controller, ovn_igmp_cmd)
        for string in re.split(r'\n+', ovn_igmp_output):
            if 'address' in string:
                igmp_ip = re.sub(r'address\s+ :\s+',
                                 '', string.rstrip())
                multicast_ips.append(igmp_ip.replace('"', ''))
        if multicast_ips:
            # Iterate over unique IP entries
            for ip in set(multicast_ips):
                data = {}
                data['GROUP'] = ip
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
        :param kwargs['server_id']
        :param kwargs['hyper_name']
        """
        ip_addresses = []
        hypervisor = ""
        if 'server_id' in kwargs:
            try:
                hypervisor = self.os_admin.servers_client.show_server(
                    kwargs['server_id']
                )['server']['OS-EXT-SRV-ATTR:hypervisor_hostname']
            except IndexError:
                raise IndexError('Seems like there is no server with id: '
                                 f'{kwargs["server_id"]}')
        else:
            if 'hyper_name' in kwargs:
                hypervisor = kwargs['hyper_name']

        hyp = self.os_admin.hypervisor_client.list_hypervisors(
            detail=True)['hypervisors']
        if hypervisor != "":
            ip_addresses = [val['host_ip'] for val in hyp
                            if hypervisor.split('.')[0]
                            in val['hypervisor_hostname']]
        else:
            ip_addresses = [val['host_ip'] for val in hyp]
        return ip_addresses

    def locate_ovs_physnets(self, node=None, keys=None):
        """Locate ovs existing physnets

        The method locate the ovs existing physnets and create a dict with
        the numa aware and non aware physnets.

        :param node: The node that the query should executed on.
        :param keys: The hiera mapping that should be queried.
        :return The numa physnets dict is returned
        """
        if node is None:
            node = self._get_hypervisor_ip_from_undercloud()[0]
        network_backend = self.discover_deployment_network_backend(node=node)
        if not keys:
            if network_backend == 'ovs':
                hiera_bridge_mapping = \
                    "neutron::agents::ml2::ovs::bridge_mappings"
            elif network_backend == 'ovn':
                hiera_bridge_mapping = "ovn::controller::ovn_bridge_mappings"
            else:
                hiera_bridge_mapping = None
            hiera_numa_mapping = "nova::compute::neutron_physnets_numa_" \
                                 "nodes_mapping"
            hiera_numa_tun = "nova::compute::neutron_tunnel_numa_nodes"
            hiera_pci_whitelist = "nova::compute::pci::passthrough"
            keys = [hiera_bridge_mapping, hiera_numa_mapping, hiera_numa_tun,
                    hiera_pci_whitelist]
        numa_phys_content = shell_utils.retrieve_content_from_hiera(node=node,
                                                                    keys=keys)
        # Identify the numa aware physnet
        numa_aware_phys = {}
        bridge_mapping = []
        numa_aware_tun = []
        pci_whitelist = []
        for physnet in numa_phys_content:
            if 'physical_network' in physnet:
                pci_whitelist = yaml.safe_load(physnet.replace('=>', ':'))
            elif '=>' in physnet:
                numa_aware_phys = yaml.safe_load(physnet.replace('=>', ':'))
            elif ':' in physnet:
                bridge_mapping = yaml.safe_load(physnet)
            else:
                numa_aware_tun = yaml.safe_load(physnet)

        numa_physnets = {'numa_aware_net': {},
                         'non_numa_aware_net': [],
                         'numa_aware_tunnel': {}}
        physnet_list = []
        """" Check type is list"""
        if not isinstance(bridge_mapping, list):
            bridge_mapping = bridge_mapping.split(',')
        for item in bridge_mapping:
            physnet = item.split(':')[0]
            physnet_list.append(physnet)

        for physnet in physnet_list:
            if physnet in numa_aware_phys.keys():
                LOG.info('The {} is a numa aware network'.format(physnet))
                numa_physnets['numa_aware_net'] = \
                    {'net': physnet, 'numa_node': numa_aware_phys[physnet][0]}
            else:
                LOG.info('The {} is a non numa aware network'.format(physnet))
                numa_physnets['non_numa_aware_net'].append(physnet)

        # Exclude sriov networks from non numa aware list
        sriov_nets = [sriov_net['physical_network']
                      for sriov_net in pci_whitelist]
        sriov_nets = list(set(sriov_nets))
        numa_physnets['non_numa_aware_net'] = \
            [non_numa for non_numa in numa_physnets['non_numa_aware_net']
             if non_numa not in sriov_nets]

        if numa_aware_tun:
            numa_physnets['numa_aware_tunnel'] = \
                {'numa_node': numa_aware_tun[0]}
        return numa_physnets

    def list_available_resources_on_hypervisor(self, hypervisor_name, nps=1):
        """List available CPU and RAM on dedicated hypervisor"""
        nc = OsClients()
        hypervisors = \
            nc.novaclient_overcloud.hypervisors.list(hypervisor_name)

        for hypervisor in hypervisors:
            if hypervisor_name in hypervisor.hypervisor_hostname:
                hypervisors = hypervisor

        self.assertTrue(hypervisors,
                        'no hypervisor conataining '
                        f'{hypervisor_name} were found'
                        if hypervisor_name else 'no hypervisors were found')

        cpu_info = hypervisors.cpu_info['topology']

        pcpu_total = cpu_info['cores'] * cpu_info['cells']
        vcpu_used = hypervisors.vcpus_used
        pcpu_used = vcpu_used // cpu_info['threads']
        pcpu_free = pcpu_total - (vcpu_used // cpu_info['threads'])
        pcpu_free_per_numa = pcpu_free // (cpu_info['cells'] * nps)
        vcpu_total = pcpu_total * cpu_info['threads']
        vcpu_used = hypervisors.vcpus_used
        vcpu_free = vcpu_total - vcpu_used
        vcpu_free_per_numa = vcpu_free // (cpu_info['cells'] * nps)
        ram_free = hypervisors.free_ram_mb

        return {'pcpu_total': pcpu_total, 'pcpu_used': pcpu_used,
                'pcpu_free': pcpu_free,
                'pcpu_free_per_numa': pcpu_free_per_numa,
                'vcpu_total': vcpu_total, 'vcpu_used': vcpu_used,
                'vcpu_free': vcpu_free,
                'vcpu_free_per_numa': vcpu_free_per_numa,
                'ram_free': ram_free}

    def discover_deployment_network_backend(self, node=None):
        """Locate deployment's network backend

        The method discovers the network backend used in deployment.
        It depends on hieradata being present on the node.

        :param node: The node that the query should executed on.
        :return The deployment network backend.
        """
        # Initialize parameters
        network_backend = 'unknown'
        hieradata_keys = [
            'enabled_services'
        ]
        if node is None:
            node = self._get_hypervisor_ip_from_undercloud()[0]
        hiera_response = \
            shell_utils.retrieve_content_from_hiera(node=node,
                                                    keys=hieradata_keys)
        # Construct a list of enabled services from response string
        enabled_services = \
            re.sub(r'\[|\]|"| ', '', hiera_response[0]).split(',')
        if 'neutron_plugin_ml2' in enabled_services:
            network_backend = 'ovs'
        elif 'neutron_plugin_ml2_ovn' in enabled_services:
            network_backend = 'ovn'
        LOG.info("Discovered network backend '{}'".format(network_backend))
        return network_backend

    def discover_mtu_network_size(self, fip=None, fixed_port=None):
        """Discover mtu network size

        Discover and return the size of MTU according to the network by
        provided ip address.
        Supports floating ip or fixed port addresses.
        For VXLAN - 8922 and for VLAN - 8972.
        For details, refer to:
        https://oswalt.dev/2014/03/mtu-considerations-for-vxlan/

        :param fip: Instance floating ip address
        :param fixed_port: Instance internal (fixed) ip address
        :return Mtu size int value
        """
        mtu = None
        try:
            if fip:
                port_net_id = \
                    self.get_internal_port_from_fip(fip)['network_id']
            if fixed_port:
                port_net_id = self.os_admin.ports_client.list_ports(
                    fixed_ips="ip_address=" + fixed_port)['ports'][0][
                        'network_id']
        except IndexError:
            err_msg = 'Unable to locate fip details - {}'.format(fip)
            raise Exception(err_msg)
        net_type = self.os_admin.networks_client.show_network(
            port_net_id)['network']['provider:network_type']
        # The number of mtu bytes size we expect to get,
        # based on the protocol we are using.
        # In case of VLAN:
        #    20 bytes taken for the IP header
        #    8 bytes taken for the ICMP header
        # In case of VXLAN:
        # In addition to the base bytes count (28):
        #    50 bytes taken for the vxlan protocol type
        # In case of GENEVE:
        # In addition to the base bytes count (28):
        #    86 bytes taken for the geneve protocol type
        # http://ipengineer.net/2014/06/vxlan-mtu-vs-ip-mtu-consideration/
        # https://www.rfc-editor.org/rfc/rfc8926.html#name-efficient-\
        # implementation
        mtu_type = {'vxlan': 8922, 'geneve': 8914, 'vlan': 8972}
        if net_type not in mtu_type:
            raise KeyError('Unable to locate network type for mtu')
        mtu = mtu_type[net_type]
        return mtu

    def fetch_nodes_passthrough_nics_info(self, nodes=None):
        """Fetch the nodes passthrough nics info

        Fetch various network interfaces information from nodes.
        The method will return a dict of the interfaces info per each node.
        A sample output will look like:

        {'192.0.10.17': {'enp5s0f2': {'bus-info': '0000:05:00.2',
                                      'driver': 'mlx5e_rep',
                                      'hw-tc-offload': 'on'},
                        'enp5s0f3': {'bus-info': '0000:05:00.3',
                                     'driver': 'mlx5e_rep',
                                     'hw-tc-offload': 'on'}},
         '192.0.10.6': {'enp5s0f2': {'bus-info': '0000:05:00.2',
                                     'driver': 'mlx5e_rep',
                                     'hw-tc-offload': 'on'},
                        'enp5s0f3': {'bus-info': '0000:05:00.3',
                                     'driver': 'mlx5e_rep',
                                     'hw-tc-offload': 'on'}}}

        :param nodes: List of ip addresses of the nodes
        :type nodes: list

        :return: Passthrough nics info
        :rtype: Dict of dicts
        """
        passthrough_nics = {}
        if nodes is None:
            nodes = self._get_hypervisor_ip_from_undercloud()
        key = ["nova::compute::pci::passthrough"]
        for node in nodes:
            passthrough_nics[node] = {}
            pci_nics = shell_utils.retrieve_content_from_hiera(node=node,
                                                               keys=key)
            pci_nics = yaml.safe_load(pci_nics[0])

            nics = []
            for pci_nic in pci_nics:
                # It is recommended to use address instead of devname for
                # SR-IOV configuration in NovaPCIPassthrough parameters
                if 'devname' in pci_nic:
                    nics.append(pci_nic['devname'])
                else:
                    nics.append(
                        shell_utils.get_nic_devname_from_address(
                            node, pci_nic['address']))

            LOG.info('Detected interfaces are - {}'.format(nics))
            cmd = ("ethtool -i {0} |grep driver;"
                   "ethtool -k {0} |grep tc-offload;"
                   "ethtool -i {0} |grep bus-info")
            for nic in nics:
                eth_output = \
                    shell_utils.run_command_over_ssh(node, cmd.format(nic))
                eth_output = eth_output.strip().split('\n')
                eth_output = dict(el.split(': ') for el in eth_output)
                passthrough_nics[node][nic] = {}
                passthrough_nics[node][nic].update(eth_output)
        return passthrough_nics

    def discover_hw_offload_nics(self, nodes=None):
        """Discover HW Offload network interfaces on hypervisor"""
        nodes_nics = self.fetch_nodes_passthrough_nics_info(nodes)
        # Check the nic driver and hw-tc-offload option.
        # Expecting - 'mlx5e_rep' (osp 16.2) or 'mlx5_core' (osp 17)
        # for the driver and 'on' for the hw-tc-offload
        mlnx_nics = {}
        for node, nics_info in nodes_nics.items():
            mlnx_nics[node] = {}
            for nic, nic_options in nics_info.items():
                if (nic_options.get('driver') in ['mlx5e_rep', 'mlx5_core']
                        and nic_options.get('hw-tc-offload') == 'on'):
                    mlnx_nics[node][nic] = {}
                    mlnx_nics[node][nic].update(nic_options)
        mlnx_nics_state = [nic for nic in mlnx_nics.items() if nic[1] != {}]
        if not mlnx_nics_state:
            raise KeyError('Mellanox hw-offload nics not detected')
        LOG.info('The HW Offload interfaces detected - {}'.format(mlnx_nics))
        return mlnx_nics

    def retrieve_ovs_dpdk_bond_details(self, node=None):
        """Retrieve OVS DPDK bond details from hypervisor

        :param node: Ip address of the node to retrieve the ovs dpdk name from.
                     If node not specified, first hypervisor will be used.
        :return Details of the ovs dpdk bond (dict)
        """
        ovs_dpdk_bonds = {}
        if node is None:
            node = self._get_hypervisor_ip_from_undercloud()[0]
        if self.get_osp_release() >= 17:
            os_net_config_cmd = 'cat /etc/os-net-config/config.yaml'
            load_f = yaml.safe_load
        else:
            os_net_config_cmd = 'cat /etc/os-net-config/config.json'
            load_f = json.loads
        content = shell_utils.run_command_over_ssh(node, os_net_config_cmd)
        os_net_data = load_f(content)
        for net_int in os_net_data['network_config']:
            if 'members' in net_int:
                for member in net_int['members']:
                    if member['type'] == 'ovs_dpdk_bond':
                        ovs_dpdk_bonds[member['name']] = member
        return ovs_dpdk_bonds

    def retrieve_lacp_ovs_bond(self, node=None):
        """Retrieve ovs bond with lacp configuration

        :param node: Ip address of the node to retrieve the configuration from.
        """
        bond_ports = []
        lacp_bonds = self.retrieve_ovs_dpdk_bond_details(node)
        for bond, bond_details in iter(lacp_bonds.items()):
            if bond_details.get('ovs_options') and \
                    'lacp' in bond_details['ovs_options']:
                for bond_port in bond_details['members']:
                    bond_ports.append(bond_port['name'])
        if not bond_ports:
            raise ValueError('LACP configuration is missing')
        return {'bond_name': bond, 'bond_ports': bond_ports}

    def get_ovs_other_config_params(self, hypervisor_ip):
        """Get ovs other_config params

        Get ovs other config params

        :param hypervisor_ip: hypervisor server
        :return dictionary with parameters
        """
        cmd = 'sudo ovs-vsctl --format=json get ' \
              'open_vswitch . other_config'

        # parse cmd command
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        # missing double quotes in json, fixing it
        # {dpdk-extra=" -n 4", dpdk-init="true", dpdk-socket-mem="4096,1024",
        # pmd-auto-lb="true", pmd-auto-lb-improvement-threshold="50",
        # pmd-auto-lb-load-threshold="70", pmd-auto-lb-rebal-interval="3",
        # pmd-cpu-mask=fc}
        output = output.replace("=", "\":\"").replace("{", "{\"").\
            replace("}", "\"}").replace(", ", "\", \"").\
            replace("\"\"", "\"")

        return json.loads(output)

    def get_number_queues_for_interface(self, hypervisor_ip, interface):
        """Get number of queues for interface

        Get number of queues for interface

        :param hypervisor_ip: hypervisor server
        :param interface: interface to get queues
        :return dictionary with parameters
        """
        cmd = 'sudo ovs-vsctl  list Interface {} | ' \
              'grep -o -P "n_rxq.{{0,4}}" | awk -F \'"\' \'{{print $2}}\''

        # parse cmd command
        output = shell_utils.run_command_over_ssh(hypervisor_ip,
                                                  cmd.format(interface))
        queues = -1
        try:
            queues = int(output)
        except Exception:
            pass
        return queues

    def get_pmd_cores_data(self, hypervisor_ip, ports_filter=None):
        """Get pmd cores data

        Return output of command: ovs-appctl dpif-netdev/pmd-rxq-show

        :param hypervisor_ip: hypervisor server
        :param ports_filter: filter only these ports if not null
        :return dictionary with information processed
        """
        cmd = 'sudo ovs-appctl dpif-netdev/pmd-rxq-show'

        # parse cmd command
        output_data = {}
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        pmd_data = {}
        pmd_regex = "pmd thread numa_id (\\d+) core_id (\\d+):"
        port_regex = "  port: ([a-zA-Z\\-0-9]+)\\s+queue-id:\\s+(\\d+) " \
                     "\\(enabled\\)\\s+pmd usage:\\s+(\\d+ %|NOT AVAIL)"
        for line in output.split("\n"):
            pmd_out = re.search(pmd_regex, line)
            port_out = re.search(port_regex, line)
            if pmd_out:
                if len(pmd_data.keys()) > 0:
                    key = "{}_{}".format(pmd_data["numa_id"],
                                         pmd_data["core_id"])
                    if len(pmd_data["queues"]) > 0:
                        output_data[key] = pmd_data
                    pmd_data = {}
                pmd_data["numa_id"] = int(pmd_out.group(1))
                pmd_data["core_id"] = int(pmd_out.group(2))
                pmd_data["queues"] = {}
            if port_out:
                queue = {}
                queue["port"] = port_out.group(1)
                queue["queue_id"] = int(port_out.group(2))
                # after rebalancing, pmd_usage can be "NOT AVAIL"
                try:
                    queue["pmd_usage"] = int(port_out.group(3).
                                             replace("%", ""))
                except ValueError:
                    queue["pmd_usage"] = -1
                if (ports_filter is None)\
                        or (ports_filter is not None
                            and queue["port"] in ports_filter):
                    key_queue = "{}_{}".format(queue["port"],
                                               queue["queue_id"])
                    pmd_data["queues"][key_queue] = queue
        if len(pmd_data.keys()) > 0:
            key = "{}_{}".format(pmd_data["numa_id"],
                                 pmd_data["core_id"])
            output_data[key] = pmd_data

        return output_data
