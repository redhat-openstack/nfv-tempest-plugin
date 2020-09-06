# Copyright 2019 Red Hat, Inc.
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

from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest.common import waiters
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestAdvancedScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestAdvancedScenarios, self).__init__(*args, **kwargs)

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestAdvancedScenarios, self).setUp()

    def test_numa_aware_vswitch(self, test='numa_aware_vswitch'):
        """Test proper vcpu allocation according to numa aware vswitch config

        The numa aware vswitch allows to configure the allocation of the
        instance vcpu by mapping the physnet to the proper numa node.

        Note!
        - The test require NUMATopologyFilter to be set.

        Note! - The test suit only for OSP Rocky version and above, since the
                numa aware vswitch feature was implemented only in OSP Stein
                version and backported to OSP Rocky.
        """
        LOG.info('Starting numa aware vswitch test.')
        LOG.info('Create resources for the test.')
        hyper = self.os_admin.hypervisor_client.list_hypervisors()[
            'hypervisors']
        kwargs = {'availability_zone': {'zone_name': 'numa_aware_avail_zone',
                                        'hyper_hosts':
                                            [hyper[0]['hypervisor_hostname']]}}
        _, key_pair = self.create_and_verify_resources(test=test,
                                                       num_servers=0,
                                                       **kwargs)
        LOG.info('Gather numa aware and non numa aware network details.')
        numas_phys = self.locate_ovs_physnets()
        if not numas_phys.get('numa_aware_net'):
            raise ValueError('Numa aware physnet configuration is missing')
        numa_net = self.locate_numa_aware_networks(numas_phys)

        resources = self.list_available_resources_on_hypervisor(
            hyper[0]['hypervisor_hostname'])
        flavor_vcpu = self.os_primary.flavors_client.show_flavor(
            self.flavor_ref)['flavor']['vcpus']
        srv_num_to_boot = resources['pcpu_free_per_numa'] // flavor_vcpu
        net_id = []
        for _ in range(srv_num_to_boot):
            net_id.append([{'uuid': numa_net}])
        kwargs = {'security_groups': self.remote_ssh_sec_groups_names,
                  'availability_zone': 'numa_aware_avail_zone',
                  'key_name': key_pair['name']}
        LOG.info('Booting instances on numa node 0. Expect to succeed.')
        numa_aware_srv = \
            self.create_server_with_fip(num_servers=srv_num_to_boot,
                                        flavor=self.flavor_ref,
                                        networks=net_id, **kwargs)
        for srv in numa_aware_srv:
            LOG.info('Instance details: fip: {}, instance_id: {}'.format(
                srv['fip'], srv['id']))
            srv['hypervisor_ip'] = self._get_hypervisor_ip_from_undercloud(
                **{'shell': '/home/stack/stackrc', 'server_id': srv['id']})[0]
            self.assertNotEmpty(srv['hypervisor_ip'],
                                "_get_hypervisor_ip_from_undercloud "
                                "returned empty ip list")

        LOG.info('Booting up another numa aware instance. Expect to fail.')
        fail_srv = self.create_server_with_fip(flavor=self.flavor_ref,
                                               srv_state='ERROR',
                                               raise_on_error=False,
                                               networks=net_id,
                                               **kwargs)
        fail_srv_state = self.os_primary.servers_client.show_server(
            fail_srv[0]['id'])['server']
        self.assertEqual(fail_srv_state['status'], 'ERROR')
        LOG.info('Check vcpu placement of numa aware instances.')
        [self.match_vcpu_to_numa_node(
            srv, srv['hypervisor_ip'],
            numa_node=numas_phys['numa_aware_net']['numa_node'])
         for srv in numa_aware_srv]
        srv_list = [srv['id'] for srv in numa_aware_srv]

        non_numa_skip_log = ('Skip "non numa aware" test phase as '
                             '"non numa aware" network was not found')
        if numas_phys.get('non_numa_aware_net'):
            non_numa_net = None
            # Exclude external network to avoid issue with booting instance
            # and assign external network and internal to the instance.
            non_numa_net = self.networks_client.list_networks(
                **{'provider:physical_network': numas_phys[
                    'non_numa_aware_net'],
                   'router:external': False})['networks']
            if non_numa_net:
                LOG.info('Test non numa aware network')
                non_numa_net = non_numa_net[0]['id']
                net_id = [[{'uuid': non_numa_net}]]
                LOG.info('Booting an non numa aware instance.'
                         'Expect to success.')
                non_numa_srv = \
                    self.create_server_with_fip(flavor=self.flavor_ref,
                                                networks=net_id, **kwargs)
                srv_list.append(non_numa_srv[0]['id'])
            else:
                LOG.warn(non_numa_skip_log)
        else:
            LOG.warn(non_numa_skip_log)

        LOG.info('Ensure all the instances are on the same hypervisor node.')
        host = [self.os_admin.servers_client.show_server(hp)['server']
                ['OS-EXT-SRV-ATTR:hypervisor_hostname'] for hp in srv_list]
        host = list(set(host))
        if len(host) > 1:
            raise ValueError("The instances should reside on a single "
                             "hypervisor. Use availability zone to reach "
                             "that state.")
        LOG.info('Migrate the instance')
        self.os_admin.servers_client.live_migrate_server(
            server_id=numa_aware_srv[0]['id'], block_migration=True,
            host=hyper[1]['hypervisor_hostname'], force=True)
        waiters.wait_for_server_status(self.servers_client,
                                       numa_aware_srv[0]['id'], 'ACTIVE')
        LOG.info('Verify instance connectivity after the cold migration.')
        self.check_instance_connectivity(ip_addr=numa_aware_srv[0]['fip'],
                                         user=self.instance_user,
                                         key_pair=key_pair['private_key'])
        second_hyper = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc',
               'server_id': numa_aware_srv[0]['id']})[0]
        self.assertNotEqual(numa_aware_srv[0]['hypervisor_ip'], second_hyper,
                            'The instance was not able to migrate to '
                            'another hypervisor')
        LOG.info('The {} instance has been migrated to the {} hypervisor'
                 .format(numa_aware_srv[0]['id'], second_hyper))
        LOG.info('Cold migration passed.')
        LOG.info('Numa aware test completed.')

    def test_pinned_srv_live_migration(self, test='pinned_srv_live_migration'):
        """Test live migration of pinned instances.

        The test performs the following actions:
        - Boot the cpu pinned instance on the first hypervisor
        - Live migrate the cpu pinned instance to the second hypervisor
          Expect live migration to success
        - Boot seconds pinned instance on the first hypervisor
        - Live migrate the first instance back to the first hypervisor
        - Verify by the virsh xml that the first vm was rescheduled on the cpu.
        """
        LOG.info('Pinned instance live migration test')
        srv1, key_pair = self.create_and_verify_resources(test=test,
                                                          use_mgmt_only=True)
        srv1_vcpus_before_migration = \
            self.get_instance_vcpu(srv1[0], srv1[0]['hypervisor_ip'])
        LOG.info('The cores of {srv} instance on the {hyper} hypervisor are '
                 '{cores}'.format(srv=srv1[0]['id'],
                                  hyper=srv1[0]['hypervisor_ip'],
                                  cores=srv1_vcpus_before_migration))

        LOG.info('Live migrate the instance to the second hypervisor')
        self.os_admin.servers_client.live_migrate_server(
            server_id=srv1[0]['id'], block_migration=True, host=None)
        waiters.wait_for_server_status(self.servers_client, srv1[0]['id'],
                                       'ACTIVE')
        self.check_instance_connectivity(ip_addr=srv1[0]['fip'],
                                         user=self.instance_user,
                                         key_pair=key_pair['private_key'])
        LOG.info('Verify the migration succeeded')
        second_hyper = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc', 'server_id': srv1[0]['id']})[0]
        self.assertNotEqual(srv1[0]['hypervisor_ip'], second_hyper,
                            'The instance was not able to migrate to '
                            'another hypervisor')
        LOG.info('The {} instance has been migrated to the {} hypervisor'
                 .format(srv1[0]['id'], second_hyper))

        mgmt_net = self.mgmt_network
        mgmt_net_id = [[{'uuid': self.test_network_dict[mgmt_net]['net-id']}]]
        kwargs = {'security_groups': self.remote_ssh_sec_groups_names,
                  'key_name': key_pair['name']}
        srv2 = self.create_server_with_fip(flavor=self.flavor_ref,
                                           networks=mgmt_net_id, **kwargs)
        self.check_instance_connectivity(ip_addr=srv2[0]['fip'],
                                         user=self.instance_user,
                                         key_pair=key_pair['private_key'])
        srv2[0]['hypervisor_ip'] = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc', 'server_id': srv2[0]['id']})[0]
        LOG.info('Boot second instance {} on the {} hypervisor'
                 .format(srv2[0]['id'], srv2[0]['hypervisor_ip']))
        srv2_vcpus = self.get_instance_vcpu(srv2[0], srv1[0]['hypervisor_ip'])
        LOG.info('The cores of {} instance on the {} hypervisor are {}'.format(
            srv2[0]['id'], srv2[0]['hypervisor_ip'], srv2_vcpus))

        LOG.info('Live migrate srv1 back to the first hypervisor')
        self.os_admin.servers_client.live_migrate_server(
            server_id=srv1[0]['id'], block_migration=True, host=None)
        waiters.wait_for_server_status(self.servers_client, srv1[0]['id'],
                                       'ACTIVE')
        self.check_instance_connectivity(ip_addr=srv1[0]['fip'],
                                         user=self.instance_user,
                                         key_pair=key_pair['private_key'])
        first_hyper = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc', 'server_id': srv1[0]['id']})[0]
        self.assertEqual(srv1[0]['hypervisor_ip'], first_hyper,
                         'The {} instance was not migrated back to the {} '
                         'hypervisor'. format(srv1[0]['id'], first_hyper))
        srv1_vcpus_after_migration = \
            self.get_instance_vcpu(srv1[0], srv1[0]['hypervisor_ip'])
        LOG.info('The cores of {} instance on the {} hypervisor after '
                 'migration are {}'.format(srv1[0]['id'], first_hyper,
                                           srv1_vcpus_after_migration))

        LOG.info('Ensure srv2 uses released cores of migrated srv1 instance')
        self.assertEqual(srv1_vcpus_before_migration, srv2_vcpus,
                         'The cores are not equal: {srv1} - {srv2}. '
                         'The second boot instance should take the same cores'
                         ' released by the migrated instance'.format(
                             srv1=srv1_vcpus_before_migration,
                             srv2=srv2_vcpus))
        LOG.info('Ensure that srv1 migrated back to the first hypervisor, '
                 'rescheduled its cores')
        self.assertNotEqual(srv2_vcpus, srv1_vcpus_after_migration,
                            'The cores are equal: {srv1_cpu} - {srv2_cpu}. '
                            'No core re-schedule detected!!! Once {srv1} '
                            'instance migrated back to {hyper} hypervisor, '
                            'its cores should differ from the cores before '
                            'the migration'
                            .format(srv1_cpu=srv1_vcpus_after_migration,
                                    srv2_cpu=srv2_vcpus,
                                    srv1=srv1[0]['id'],
                                    hyper=srv1[0]['hypervisor_ip']))
        LOG.info('The pinned instance live migration test passed')

    def test_pinned_and_non_pinned_srv(self, test='pinned_and_non_pinned_srv'):
        """Test pinned and non pinned instances on the same compute

        The test performs the following actions:
        - Boot pinned instance (using specific flavor)
        - Boot non pinned instance (using specific flavor) on the same host
        - Ensure the instances booted on the same hypervisor
        - Takes the allocated cpu for the intstances
        - Takes the dedicated and shared cpu set from hypervisor
        - Compares between them to ensure that instances uses proper cpu
        """
        LOG.info('Pinned and non pinned instances test')
        LOG.info('Create flavors for pinned and non pinned instances')
        flavors_id = []
        flavors = [{'name': 'flavor_dedicated', 'vcpus': 4,
                    'extra_specs': {'hw:mem_page_size': "large",
                                    'resources:PCPU': '4',
                                    'hw:emulator_threads_policy': 'share'}},
                   {'name': 'flavor_shared', 'vcpus': 2,
                    'extra_specs': {'hw:mem_page_size': "large",
                                    'resources:VCPU': '2',
                                    'hw:emulator_threads_policy': 'share'}}]
        for flavor in flavors:
            flavors_id.append(self.create_flavor(**flavor))
        srv_details = {'srv_details': {0: {'flavor': flavors_id[0]},
                                       1: {'flavor': flavors_id[1]}}}
        hyper = self.hypervisor_client.list_hypervisors()['hypervisors']
        kwargs = {'availability_zone':
                  {'hyper_hosts': [hyper[0]['hypervisor_hostname']]}}
        kwargs.update(srv_details)
        servers, _ = self.create_and_verify_resources(test=test, num_servers=2,
                                                      use_mgmt_only=True,
                                                      **kwargs)
        LOG.info('Ensure all the instances are on the same hypervisor node.')
        srv_id = []
        for srv in servers:
            srv_id.append(srv['id'])
        hyper = [self.os_admin.servers_client.show_server(hp)['server']
                 ['OS-EXT-SRV-ATTR:hypervisor_hostname'] for hp in srv_id]
        hyper = list(set(hyper))
        if len(hyper) > 1:
            raise ValueError("The instances should reside on a single "
                             "hypervisor. Use aggregate to reach that state.")
        LOG.info('Check instances vcpu placement')
        srv_dedicated = self.get_instance_vcpu(servers[0],
                                               servers[0]['hypervisor_ip'])
        srv_shared = self.get_instance_vcpu(servers[1],
                                            servers[1]['hypervisor_ip'])
        LOG.info('Take the dedicated and share cpu set from hypervisor')
        dedicated_set, shared_set = self.locate_dedicated_and_shared_cpu_set()
        LOG.info('CHeck results')
        test_results = []
        if not all(cpu in shared_set for cpu in srv_shared):
            test_results.append('The vcpu\'s used by the shared instance - {} '
                                'does not exist in shared '
                                'set - {}.'.format(srv_shared, shared_set))
        if not all(cpu in dedicated_set for cpu in srv_dedicated):
            test_results.append('The vcpu\'s used by the dedicated instance '
                                '- {} does not exist in dedicated set '
                                '- {}.'.format(srv_dedicated, dedicated_set))
        self.assertEmpty(test_results, test_results)
        LOG.info('Pinned and non pinned instances test passed')
