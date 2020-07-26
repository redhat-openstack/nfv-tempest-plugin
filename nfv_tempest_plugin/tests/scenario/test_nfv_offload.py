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

from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
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

    def test_offload_ovs_config(self):
        """Check ovs config for offload on all hypervisors

        """
        # Command to check if hw-offload is enabled in OVS
        cmd = ("sudo ovs-vsctl get open_vswitch . "
               "other_config:hw-offload")
        # Retrieve all hypvervisors
        hypervisors = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')
        # Intialize results list
        result = []
        # Expected result is a list of dicts, each dict contains
        # a key which is hypervisor's IP and the value 'true'
        # Example:
        # [{192.0.60.1: 'true'}, {192.0.60.2: 'true'}]
        expected_result = [{ip: 'true'} for ip in hypervisors]
        for hypervisor in hypervisors:
            out = shell_utils.run_command_over_ssh(hypervisor, cmd)
            if out:
                # Strip newlines and remove double quotes
                output = out.rstrip().replace('"', '')
            # HW-Offload not enabled if no text returned
            else:
                output = 'false'
            LOG.info("Hypervisor '{h}' is OVS HW-offload "
                     "capable: '{r}'".format(h=hypervisor,
                                             r=output))
            result.append({hypervisor: output})
        msg = "Not all hypervisors have OVS HW-Offload enabled"
        self.assertItemsEqual(expected_result, result, msg)

    def test_offload_nic_eswitch_mode(self, test='offload'):
        """Check eswitch mode of nic for offload on all hypervisors

        :param test: Test name from the external config file.
        """
        test_dict = self.test_setup_dict[test]
        if 'offload_nics' in test_dict:
            offload_nics = test_dict['offload_nics']
        else:
            raise ValueError('offload_nics is not defined in offload test')
        # Retrieve all hypvervisors
        hypervisors = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')
        # ethtool cmd to retrieve PCI bus of interface
        ethtool_cmd = ("sudo ethtool -i {} | grep bus-info "
                       "| cut -d ':' -f 2,3,4 | awk '{{$1=$1}};1'")
        # devlink cmd to retrieve switch mode of interface
        devlink_cmd = "sudo devlink dev eswitch show pci/{}"
        # Intialize results list
        result = []
        # Expected result is a list of dicts containing a dict of
        # hypervisor's IP, its offload nics as keys and the value 'true'
        # Example:
        # [{'192.0.160.1': [{'p6p1': 'true'}, {'p6p2': 'true'}]},
        #  {'192.0.160.2': [{'p6p1': 'true'}, {'p6p2': 'true'}]}]
        expected_result = [{ip: [{nic: 'true'} for nic in offload_nics]}
                           for ip in hypervisors]
        for hypervisor in hypervisors:
            dev_result = []
            for nic in offload_nics:
                pci = shell_utils.run_command_over_ssh(hypervisor,
                                                       ethtool_cmd.format(nic))
                dev_query = shell_utils.\
                    run_command_over_ssh(hypervisor,
                                         devlink_cmd.format(pci))
                if 'switchdev' in dev_query:
                    output = 'true'
                else:
                    output = 'false'
                LOG.info("Hypervisor '{h}' NIC '{n}' is in switchdev mode: {r}"
                         .format(h=hypervisor, n=nic, r=output))
                dev_result.append({nic: output})
            result.append({hypervisor: dev_result})
        msg = "Not all hypervisors contains nics in switchev mode"
        self.assertItemsEqual(expected_result, result, msg)

    def test_offload_ovs_flows(self, test='offload_flows'):
        """Check OVS offloaded flows

        The following test deploy vms, on hw-offload computes.
        It sends async ping and check offload flows exist in ovs.

        :param test: Test name from the external config file.
        """

        LOG.info('Start test_offload_ovs_flows test.')
        LOG.info('test_offload_ovs_flows create vms')
        # Create servers
        servers, key_pair = self.create_and_verify_resources(test=test,
                                                             num_servers=4)
        cmd = 'sudo ovs-appctl dpctl/dump-flows type=offloaded'
        # Iterate over created servers
        for server in servers:

            shell_utils.continuous_ping(server['fip'],
                                        duration=30)
            LOG.info('test_offload_ovs_flows verify flows on geust {}'.
                     format(server['fip']))

            out = shell_utils.\
                run_command_over_ssh(server['hypervisor_ip'],
                                     cmd)
            ports =  \
                self.os_admin.ports_client.list_ports(device_id=server['id'])
            msg = ('Port with mac address {} is expected to be part of '
                   'offloaded flows')
            for port in ports['ports']:
                if 'capabilities' in port['binding:profile'] and 'switchdev'\
                        in port['binding:profile']['capabilities']:
                    self.assertIn(port['mac_address'], out,
                                  msg.format(port['mac_address']))
        # Pings are running check flows exist
        # Retrieve all hypvervisors
        hypervisors = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')
        # Command to check offloaded flows in OVS
        cmd = 'sudo ovs-appctl dpctl/dump-flows type=offloaded'
        for hypervisor in hypervisors:
            out = shell_utils.run_command_over_ssh(hypervisor,
                                                   cmd)
            msg = 'Hypervisor {} has no offloaded flows in OVS'.format(
                hypervisor)
            self.assertNotEmpty(out, msg)
            LOG.info('Hypercisor {} has offloaded flows in OVS'.format(
                hypervisor))

        # send stop statistics signal
        shell_utils.stop_continuous_ping()
