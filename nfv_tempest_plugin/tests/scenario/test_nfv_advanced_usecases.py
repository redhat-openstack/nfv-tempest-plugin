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
        - The test require the use of aggregation.
          - Aggregation host should be defined in test config.
          - Metadata for the aggregation should be defined in test config.
          - The flavor should have the aggregation metadata set.

        Note! - The test suit only for OSP Rocky version and above, since the
                numa aware vswitch feature was implemented only in OSP Stein
                version and backported to OSP Rocky.
        """
        LOG.info('Starting numa aware vswitch test.')
        LOG.info('Create resources for the test.')
        no_srv, key_pair = self.create_and_verify_resources(test=test,
                                                            num_servers=0)
        LOG.info('Gather numa aware and non numa aware network details.')
        numas_phys = self.locate_ovs_physnets()
        if not numas_phys.get('numa_aware_net'):
            raise ValueError('Numa aware physnet configuration is missing')
        numa_net = self.locate_numa_aware_networks(numas_phys)

        hyper = self.os_admin.hypervisor_client.list_hypervisors()[
            'hypervisors'][0]['hypervisor_hostname']
        resources = self.list_available_resources_on_hypervisor(hyper)
        self._create_and_set_aggregate(test, [hyper], 'test={}'.format(test))
        extra_specs = \
            {'extra_specs': {'hw:mem_page_size': str("large"),
                             'hw:cpu_policy': str("dedicated"),
                             'aggregate_instance_extra_specs:test': test}}
        srv_num_to_boot = resources['cpu_free_per_numa'] // 6
        numa_flavor = self.create_flavor(name='numa0_aware', vcpus=6,
                                         **extra_specs)
        net_id = []
        for _ in range(srv_num_to_boot):
            net_id.append([{'uuid': numa_net}])
        kwargs = {'security_groups': self.remote_ssh_sec_groups_names,
                  'key_name': key_pair['name']}
        LOG.info('Booting instances on numa node 0. Expect to succeed.')
        numa0_srv = self.create_server_with_fip(num_servers=srv_num_to_boot,
                                                flavor=numa_flavor,
                                                networks=net_id,
                                                **kwargs)
        for srv in numa0_srv:
            LOG.info('Instance details: fip: {}, instance_id: {}'.format(
                srv['fip'], srv['id']))
            srv['hypervisor_ip'] = self._get_hypervisor_ip_from_undercloud(
                **{'shell': '/home/stack/stackrc', 'server_id': srv['id']})[0]
            self.assertNotEmpty(srv['hypervisor_ip'],
                                "_get_hypervisor_ip_from_undercloud "
                                "returned empty ip list")

        LOG.info('Booting up another instance on numa node 0. Expect to fail.')
        fail_srv = self.create_server_with_fip(flavor=numa_flavor,
                                               srv_state='ERROR',
                                               raise_on_error=False,
                                               networks=net_id)
        fail_srv_state = self.os_primary.servers_client.show_server(
            fail_srv[0]['id'])['server']
        self.assertEqual(fail_srv_state['status'], 'ERROR')
        LOG.info('Check placement of instances vcpu on NUMA node 0.')
        [self.match_vcpu_to_numa_node(srv, srv['hypervisor_ip'],
                                      numa_node='0') for srv in numa0_srv]
        srv_list = [srv['id'] for srv in numa0_srv]

        if 'non_numa_aware_net' in numas_phys:
            LOG.info('Test "non numa aware network".')
            numa1_net = self.networks_client.list_networks(
                **{'provider:physical_network': numas_phys[
                    'non_numa_aware_net']})['networks'][0]['id']
            net_id = [[{'uuid': numa1_net}]]
            LOG.info('Booting an instance on numa node 1. Expect to success.')
            numa1_srv = self.create_server_with_fip(flavor=numa_flavor,
                                                    networks=net_id,
                                                    fip=False)
            LOG.info('Check placement of instances vcpu on NUMA node 1.')
            numa1_srv[0]['hypervisor_ip'] = \
                self._get_hypervisor_ip_from_undercloud(
                    **{'shell': '/home/stack/stackrc',
                       'server_id': numa1_srv[0]['id']})[0]
            LOG.info('Check placement of instance vcpu on NUMA node 1.')
            self.match_vcpu_to_numa_node(numa1_srv[0],
                                         numa1_srv[0]['hypervisor_ip'],
                                         numa_node='1')
            srv_list.append(numa1_srv[0]['id'])
        else:
            LOG.warn('Skip "non numa aware" test phase as "non numa aware" '
                     'network was not found')

        LOG.info('Ensure all the instances are on the same hypervisor node.')
        hyper = [self.os_admin.servers_client.show_server(hp)['server']
                 ['OS-EXT-SRV-ATTR:hypervisor_hostname'] for hp in srv_list]
        hyper = list(set(hyper))
        if len(hyper) > 1:
            raise ValueError("The instances should reside on a single "
                             "hypervisor. Use aggregate to reach that state.")

        LOG.info('Resize instance to another flavor for cold migration, as'
                 ' current flavor holds aggregate settings.')
        extra_specs = {'extra_specs': {'hw:mem_page_size': str("large")}}
        migration_flavor = self.create_flavor(name='migration_flavor',
                                              vcpus='6', **extra_specs)
        self.servers_client.resize_server(server_id=numa0_srv[0]['id'],
                                          flavor_ref=migration_flavor)
        waiters.wait_for_server_status(self.servers_client, numa0_srv[0]['id'],
                                       'VERIFY_RESIZE')
        self.servers_client.confirm_resize_server(server_id=numa0_srv[0]['id'])
        waiters.wait_for_server_status(self.servers_client, numa0_srv[0]['id'],
                                       'ACTIVE')
        LOG.info('Migrate the instance')
        self.os_admin.servers_client.migrate_server(
            server_id=numa0_srv[0]['id'])
        waiters.wait_for_server_status(self.servers_client, numa0_srv[0]['id'],
                                       'VERIFY_RESIZE')
        LOG.info('Confirm instance resize after the cold migration.')
        self.servers_client.confirm_resize_server(server_id=numa0_srv[0]['id'])
        LOG.info('Verify instance connectivity after the cold migration.')
        self.check_instance_connectivity(ip_addr=numa0_srv[0]['fip'],
                                         user=self.instance_user,
                                         key_pair=key_pair['private_key'])
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

        mgmt_net = self.test_network_dict['public']
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
