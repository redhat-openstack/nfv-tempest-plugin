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

import time

from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestLacpScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestLacpScenarios, self).__init__(*args, **kwargs)
        self.instance = None
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestLacpScenarios, self).setUp()
        """ pre setup creations and checks read from config files """

    def test_deployment_lacp(self, test='deployment_lacp'):
        """Check that lacp bonding is properly configured"""
        LOG.info('Starting deployment_lacp test.')

        hypervisor_ip = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')[0]

        config_dict={}
        if 'config_dict' in self.test_setup_dict[test]:
            config_dict=self.test_setup_dict[test]['config_dict'][0]

        cmd = 'sudo ovs-appctl bond/show {0} | egrep "^bond_mode|^lacp_status|^lacp_fallback_ab"; sudo ovs-appctl lacp/show {0} | egrep "lacp_time"'.format(config_dict['bond_name'])
        output = self._run_command_over_ssh(hypervisor_ip, cmd).replace('\t','').replace(' ','').split('\n')
        bond_data = {}
        for i in range(len(output)):
            data=output[i].split(':')
            if (len(data) == 2):
                bond_data[data[0]]=data[1]

        self.assertEqual(len(bond_data),4)
        self.assertEqual(bond_data['bond_mode'],config_dict['bond_mode'])
        self.assertEqual(bond_data['lacp_status'],config_dict['lacp_status'])
        self.assertEqual(bond_data['lacp_time'],config_dict['lacp_time'])
        self.assertEqual(bond_data['lacp_fallback_ab'],config_dict['lacp_fallback_ab'])
        return True
