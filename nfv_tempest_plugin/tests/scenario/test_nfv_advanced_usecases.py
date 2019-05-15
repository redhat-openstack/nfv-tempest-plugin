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
        - The test require configuration of numa nodes networks.

        Note! - The test suit only for RHOS version 13 and up, since the
                numa aware vswitch feature was implemented only in version 14
                and backported to 13.
        """
        LOG.info('Starting numa aware vswitch test.')
        if 'numas_net' not in self.test_setup_dict[test] \
                and 'numa0' in self.test_setup_dict[test]['numas_net'] \
                and 'numa1' in self.test_setup_dict[test]['numas_net']:
            raise ValueError('The "numas_net" config is missing for test')
        LOG.info('Booting instances to fill up the numa node 0.')
        numa0_srv, key_pair = \
            self.create_and_verify_resources(test=test, num_servers=2,
                                             use_mgmt_only=True)
        LOG.info('Booting up another instance on numa node 0. Expect to fail.')
        numa0_net = self.networks_client.list_networks(
            **{'name': self.test_setup_dict[test]['numas_net']['numa0']})[
            'networks'][0]['id']
        net_id = [{'uuid': numa0_net}]
        fail_srv = self.create_server(flavor=self.flavor_ref, wait_until=None,
                                      networks=net_id)
        waiters.wait_for_server_status(self.os_primary.servers_client,
                                       fail_srv['id'], 'ERROR',
                                       raise_on_error=False)
        fail_srv_state = self.os_primary.servers_client.show_server(
            fail_srv['id'])['server']
        self.assertEqual(fail_srv_state['status'], 'ERROR')
        numa1_net = self.networks_client.list_networks(
            **{'name': self.test_setup_dict[test]['numas_net']['numa1']})[
            'networks'][0]['id']
        net_id = [{'uuid': numa1_net}]
        LOG.info('Booting an instance on numa node 1. Expect to success.')
        numa1_srv = self.create_server(flavor=self.flavor_ref,
                                       wait_until='ACTIVE', networks=net_id)
        LOG.info('Ensure all the instances are on the same hypervisor node.')
        srv_list = [srv['id'] for srv in numa0_srv]
        srv_list.append(numa1_srv['id'])
        hyper = [self.os_admin.servers_client.show_server(hp)['server']
                 ['OS-EXT-SRV-ATTR:hypervisor_hostname'] for hp in srv_list]
        hyper = list(set(hyper))
        if len(hyper) > 1:
            raise ValueError("The instances should reside on a single "
                             "hypervisor. Use aggregate to reach that state.")
        LOG.info('Check placement of instances vcpu on NUMA node 0.')
        [self._check_vcpu_from_dumpxml(srv, srv['hypervisor_ip'],
                                       cell_id='0') for srv in numa0_srv]
        LOG.info('Check placement of instances vcpu on NUMA node 1.')
        numa1_srv['hypervisor_ip'] = self._get_hypervisor_ip_from_undercloud(
            **{'shell': '/home/stack/stackrc',
               'server_id': numa1_srv['id']})[0]
        self._check_vcpu_from_dumpxml(numa1_srv, numa1_srv['hypervisor_ip'],
                                      cell_id='1')
