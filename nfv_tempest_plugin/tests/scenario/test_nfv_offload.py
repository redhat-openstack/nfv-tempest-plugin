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

import json

from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest.common import waiters
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestNfvOffload(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestNfvOffload, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(TestNfvOffload, self).setUp()

    def test_offload_ovs_config(self, test="offload"):
        """Check ovs config for offload

        :param test: Test name from the external config file.
        :param node: Name of the offload compute node, if not provided
                     all compute nodes will be used
        """
        hyper_kwargs = {'shell': '/home/stack/stackrc'}
        configs = self.test_setup_dict['offload']['offload_config']
        for item in configs:
            if item.get('node'):
                hyper_kwargs['hyper_name'] = item.get('node')
            hypervisor_ip = self._get_hypervisor_ip_from_undercloud(**hyper_kwargs)
            for ip in hypervisor_ip:
                cmd = "sudo ovs-vsctl get open_vswitch . other_config:hw-offload"
                out = self._run_command_over_ssh(ip, cmd)
                msg = "other_config:hw-offload is set as 'true' in ovsdb of node %s" % ip
                self.assertIn("true", out, msg)

    def test_offload_nic_eswitch_mode(self, test="offload"):
        """Check eswitch mode of nic for offload

        :param test: Test name from the external config file.
        :param node: Name of the offload compute node, if not provided
                     all compute nodes will be used
        """
        hyper_kwargs = {'shell': '/home/stack/stackrc'}
        configs = self.test_setup_dict['offload']['offload_config']
        for item in configs:
            if item.get('node'):
                hyper_kwargs['hyper_name'] = item.get('node')
            nics = item.get('nics')
            self.assertIsNotNone(nics, 'nics should be provided in offload tests-setup')
            hypervisor_ip = self._get_hypervisor_ip_from_undercloud(**hyper_kwargs)
            for ip in hypervisor_ip:
                for nic in nics:
                    cmd = "sudo ethtool -i " + nic + " | grep bus-info | cut -d ':' -f 2,3,4 | awk '{$1=$1};1'"
                    out = self._run_command_over_ssh(ip, cmd)
                    cmd = "sudo devlink dev eswitch show pci/" + out
                    out = self._run_command_over_ssh(ip, cmd)
                    LOG.info(out)
                    msg = 'switchdev is not enabled for nic %s of node %s' % (nic, ip)
                    self.assertIn('switchdev', out, msg)
