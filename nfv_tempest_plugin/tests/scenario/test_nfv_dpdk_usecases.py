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

import json
import time

from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config
from tempest import exceptions

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestDpdkScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestDpdkScenarios, self).__init__(*args, **kwargs)
        self.instance = None
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id
        self.maxqueues = None

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestDpdkScenarios, self).setUp()
        try:
            self.maxqueues = super(TestDpdkScenarios, self) \
                ._check_number_queues()
        except Exception:
            print("Hypervisor OVS not configured with MultiQueue")
        """ pre setup creations and checks read from config files """

    def _test_queue_functionality(self, queues):
        """Checks DPDK queues functionality

        Booting number of instances with various number of cpus based on the
        setup queues number.
        """

        msg = "Hypervisor OVS not configured with MultiQueue"
        self.assertIsNotNone(self.maxqueues, msg)

        extra_specs = {'extra_specs': {'hw:mem_page_size': str("large"),
                                       'hw:cpu_policy': str("dedicated")}}
        if queues == "min":
            queues = self.maxqueues - 2
        elif queues == "odd":
            queues = self.maxqueues - 1
        elif queues == 'max':
            queues = self.maxqueues + 2
        else:
            queues = self.maxqueues

        queues_flavor = self.create_flavor(name='test-queues', vcpus=queues,
                                           **extra_specs)
        servers, key_pair = \
            self.create_server_with_resources(test='check-multiqueue-func',
                                              flavor=queues_flavor)

        msg = "%s instance is not reachable by ping" % servers[0]['fip']
        self.assertTrue(self.ping_ip_address(servers[0]['fip']), msg)
        self.assertTrue(self.get_remote_client(
            servers[0]['fip'], private_key=key_pair['private_key']))
        return True

    def _test_live_migration_block(self, test_setup_migration=None):
        """Method boots an instance and wait until ACTIVE state

        Migrates the instance to the next available hypervisor.
        """

        extra_specs = {'extra_specs': {'hw:mem_page_size': str("large")}}
        migration_flavor = self.create_flavor(name='live-migration', vcpus='2',
                                              **extra_specs)
        servers, key_pair = \
            self.create_server_with_resources(test=test_setup_migration,
                                              flavor=migration_flavor,
                                              use_mgmt_only=True)

        host = self.os_admin.servers_client.show_server(
            servers[0]['id'])['server']['OS-EXT-SRV-ATTR:hypervisor_hostname']
        """ Run ping before migration """
        msg = "Timed out waiting for %s to become reachable" % \
              servers[0]['fip']
        self.assertTrue(self.ping_ip_address(servers[0]['fip']), msg)
        """ Migrate server """
        self.os_admin.servers_client.live_migrate_server(
            server_id=servers[0]['id'], block_migration=True, host=None)
        """ Switch hypervisor id (compute-0 <=> compute-1) """
        count = 1
        if host.find('0') > 0:
            dest = list(host)
            dest[dest.index('0')] = '1'
            dest = ''.join(dest)
        else:
            dest = list(host)
            dest[dest.index('1')] = '0'
            dest = ''.join(dest)
        while count < 30:
            count += 1
            time.sleep(3)
            if dest == self\
                    .os_admin.servers_client.show_server(servers[0][
                    'id'])['server']['OS-EXT-SRV-ATTR:hypervisor_hostname']:
                """ Run ping after migration """
                self.assertTrue(self.ping_ip_address(servers[0]['fip']), msg)
                return True
        return False

    def _test_multicast_traffic(self, test_multicast):
        """The method boots three instances, runs mcast traffic between them"""
        LOG.info('Starting multicast test.')

        kwargs = {}
        self.assertTrue(test_multicast in self.test_setup_dict,
                        "Test requires {0} configuration "
                        "in external config file".format(test_multicast))

        flavor_exists = super(TestDpdkScenarios,
                              self).check_flavor_existence(test_multicast)
        if flavor_exists is False:
            flavor_name = self.test_setup_dict[test_multicast]['flavor']
            self.flavor_ref = \
                super(TestDpdkScenarios,
                      self).create_flavor(**self.test_flavor_dict[flavor_name])

        if 'availability-zone' in self.test_setup_dict[test_multicast]:
            kwargs['availability_zone'] = \
                self.test_setup_dict[test_multicast]['availability-zone']

        """
        Prepare and boot an Instance
        """
        keypair = self.create_keypair()
        self.key_pairs[keypair['name']] = keypair
        super(TestDpdkScenarios, self)._create_test_networks()
        if 'router' in self.test_setup_dict['multicast']:
            if self.test_setup_dict['multicast']['router']:
                super(TestDpdkScenarios, self)._add_subnet_to_router()
        kwargs['user_data'] = super(TestDpdkScenarios,
                                    self)._prepare_cloudinit_file()
        kwargs['key_name'] = keypair['name']

        servers = {}
        mcast_srv = ["traffic_runner", "listener1", "listener2"]
        for server in mcast_srv:
            LOG.info('Booting %s instance.' % server)

            security = super(TestDpdkScenarios, self)._set_security_groups()
            if security is not None:
                kwargs['security_groups'] = security
            kwargs['networks'] = super(
                TestDpdkScenarios, self)._create_ports_on_networks(**kwargs)[0]
            try:
                # ToDo: Change the server creation 'for loop' to servers list.
                self.instance = self.create_server(name=server,
                                                   image_id=self.image_ref,
                                                   flavor=self.flavor_ref,
                                                   wait_until='ACTIVE',
                                                   **kwargs)
            except exceptions.BuildErrorException:
                raise

            fip = dict()
            fip['ip'] = self.instance['addresses'][self.test_network_dict[
                'public']][0]['addr']
            if 'router' in self.test_setup_dict['multicast']:
                if self.test_setup_dict['multicast']['router']:
                    fip = self.create_floating_ip(self.instance,
                                                  self.public_network)
            self.instance['fip'] = fip['ip']
            servers[server] = self.instance

        for server in mcast_srv:
            if server not in servers:
                LOG.error('Instance %s missing from the servers list' % server)
                return False

        """
        Start multicast listeners
        """
        mcast_group = '224.0.0.1'
        mcast_port = '10000'
        mcast_msg = 'mcast_pass'
        mcast_output = '/tmp/output'
        get_mcast_results = 'cat %s' % mcast_output
        for key, value in servers.iteritems():
            if ('listener1' in key) or ('listener2' in key):
                LOG.info('Copying and executing multicast script to %s.' % key)

                # The method is a temporary solution.
                # ToDo: Remove once config-drive will be implemented.
                copy = self.copy_file_to_remote_host(value['fip'],
                                                     ssh_key=keypair[
                                                         'private_key'],
                                                     files='mcast_receive.py',
                                                     src_path='tests_scripts',
                                                     dst_path='/tmp')
                LOG.info(copy)
                ssh_source = self.get_remote_client(value['fip'],
                                                    private_key=keypair[
                                                        'private_key'])
                ssh_source.exec_command(
                    'python /tmp/mcast_receive.py -g %s -p %s > %s &'
                    % (mcast_group, mcast_port, mcast_output))
        """
        Start multicast traffic runner
        """
        for key, value in servers.iteritems():
            if 'traffic_runner' in key:
                LOG.info('Copying and executing multicast script to %s.' % key)

                # The method is a temporary solution.
                # ToDo: Remove once config-drive will be implemented.
                copy = self.copy_file_to_remote_host(value['fip'],
                                                     ssh_key=keypair[
                                                         'private_key'],
                                                     files='mcast_send.py',
                                                     src_path='tests_scripts',
                                                     dst_path='/tmp')
                LOG.info(copy)
                ssh_source = self.get_remote_client(value['fip'],
                                                    private_key=keypair[
                                                        'private_key'])
                ssh_source.exec_command(
                    'python /tmp/mcast_send.py -g %s -p %s -m %s'
                    % (mcast_group, mcast_port, mcast_msg))

        """
        Reading the listeners output files
        """
        for key, value in servers.iteritems():
            if ('listener1' in key) or ('listener2' in key):
                LOG.info('Reading results from %s instance.' % key)

                ssh_source = self.get_remote_client(value['fip'],
                                                    private_key=keypair[
                                                        'private_key'])
                output = ssh_source.exec_command(get_mcast_results)
                results = output.rstrip('\n')
                results_msg = '%s unable to receive multicast traffic.' % key
                self.assertEqual(results, mcast_msg, results_msg)
                LOG.info('%s received multicast traffic.' % key)
        LOG.info('Both listener1 and listener2 received multicast traffic')
        return True

    def test_min_queues_functionality(self):
        msg = "Could not create, ping or ssh to the instance with flavor " \
              "contains vcpus smaller than allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="min"), msg)

    def test_equal_queues_functionality(self):
        msg = "Could not create, ping or ssh to the instance with flavor " \
              "contains vcpus equal to allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="equal"), msg)

    def test_max_queues_functionality(self):
        msg = "Could not create, ping or ssh to the instance with flavor " \
              "contains vcpus max to allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="max"), msg)

    def test_odd_queues_functionality(self):
        msg = "Could not create, ping or ssh to the instance with flavor " \
              "contains odd number of vcpus"
        self.assertTrue(self._test_queue_functionality(queues="odd"), msg)

    def test_live_migration_block(self):
        """Make sure CONF.compute_feature_enabled.live_migration is True"""
        msg = "Live migration Failed"
        self.assertTrue(self._test_live_migration_block(
            test_setup_migration="test_live_migration_basic"), msg)

    def test_multicast(self):
        msg = "Multicast test failed. Check log for more details."
        self.assertTrue(self._test_multicast_traffic("multicast"), msg)

    def test_rx_tx(self, test='rx_tx'):
        """Test RX/TX on the instance vs nova configuration

        The test compares RX/TX value from the dumpxml of the running
        instance vs values of the overcloud nova configuration

        Note! - The test suit only for RHOS version 14 and up, since the
                rx/tx feature was implemented only in version 14.
        """

        servers, key_pair = self.create_and_verify_resources(test=test)

        conf = self.test_setup_dict['rx_tx']['config_dict'][0]
        config_path = conf['config_path']
        check_section = conf['check_section']
        check_value = conf['check_value']

        for srv in servers:
            return_value = self.\
                compare_rx_tx_to_overcloud_config(srv, srv['hypervisor_ip'],
                                                  config_path,
                                                  check_section,
                                                  check_value)
            self.assertTrue(return_value, 'The rx_tx test failed. '
                                          'The values of the instance and '
                                          'nova does not match.')

    def test_derived_parameters(self):
        """Test Derived Parameters

        The test compares derived parameters generated from intrsopection data
        with the current asggined values

        Note! - The test requires an external file containg all parameters
                in a JSON format.
        """

        retrive_host_params = {
            'IsolCpusList': {'action': 'command',
                             'cmd': ("sudo cat /etc/tuned/bootcmdline | "
                                     "grep -P -o 'nohz_full=.+?\s{1,}' | "
                                     "sed 's/nohz_full=//'")},
            'KernelArgs': {'action': 'command',
                           'cmd': 'sudo cat /proc/cmdline'},
            'NovaReservedHostMemory': {'action': 'ini',
                                       'file_path': ('/var/lib/config-data/'
                                                     'puppet-generated/nova_'
                                                     'libvirt/etc/nova/'
                                                     'nova.conf'),
                                       'section': 'DEFAULT',
                                       'value': 'reserved_host_memory_mb'},
            'NovaVcpuPinSet': {'action': 'ini',
                               'file_path': ('/var/lib/config-data/puppet-'
                                             'generated/nova_libvirt/etc/nova/'
                                             'nova.conf'),
                               'section': 'DEFAULT',
                               'value': 'vcpu_pin_set'},
            'OvsDpdkCoreList': {'action': 'command',
                                'cmd': ("sudo pgrep ovsdb-server | xargs "
                                        "taskset -cp | grep -P -o '\d+' | "
                                        "tail -n +2 | paste -s -d, -")},
            'OvsDpdkSocketMemory': {'action': 'command',
                                    'cmd': ("sudo ovs-vsctl get Open_vSwitch "
                                            ". other_config:dpdk-socket-mem")},
            'OvsPmdCoreList': {'action': 'command',
                               'cmd': ("sudo ovs-appctl dpif-netdev/pmd-rxq"
                                       "-show | grep core_id | "
                                       "cut -d ' ' -f 6 | "
                                       "sed -e 's/://' | paste -s -d, -")},
        }

        derived_params = CONF.hypervisor.derived_parameters_json
        host_params = {}
        failures = []

        with open(derived_params) as stream:
            derived_params = json.load(stream)

        hypervisor_ip = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')[0]
        # Retrieve parameter values from current deployment and compare
        for param in retrive_host_params:
            if retrive_host_params[param]['action'] is 'command':
                cmd = retrive_host_params[param]['cmd']
                result = self._run_command_over_ssh(hypervisor_ip, cmd)
            elif retrive_host_params[param]['action'] is 'ini':
                file_path = retrive_host_params[param]['file_path']
                section = retrive_host_params[param]['section']
                value = retrive_host_params[param]['value']
                result = self._get_value_from_ini_config(hypervisor_ip,
                                                         file_path, section,
                                                         value)
            host_params[param] = result.strip('\n').strip('"').strip()
            if param == 'OvsDpdkCoreList':
                # Substitute dash with a comma to compare derived with host
                derived_params[param] = host_params[param].replace('-', ',')
            if host_params[param] != str(derived_params[param]) and \
               str(derived_params[param]) not in host_params[param]:
                error = ("Derived parameter {p} is {d_p} is not equal to "
                         "{h_p}").format(p=param,
                                         d_p=derived_params[param],
                                         h_p=host_params[param])
                failures.append(error)
        if failures:
            raise Exception(failures)
        else:
            return True
