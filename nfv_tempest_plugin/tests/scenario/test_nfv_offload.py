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

import time

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
        hypervisors = self._get_hypervisor_ip_from_undercloud()
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

    def test_offload_nic_eswitch_mode(self):
        """Check eswitch mode of nic for offload on all hypervisors

        By default, offload nics are auto discovered.
        But if the used would like to not perform the autodiscover and
        provide the nics, it could be done by modifying the
        CONF.nfv_plugin_options.offload_nics param in deployer-input file.
        """
        LOG.info('Starting offload_nic_eswitch_mode test')
        # Retrieve all hypervisors
        hypervisors = self._get_hypervisor_ip_from_undercloud()
        offload_nics = CONF.nfv_plugin_options.offload_nics
        if not offload_nics:
            LOG.info('The offload nics are not provided. Detecting...')
            offload_nics = self.discover_hw_offload_nics(hypervisors)
        LOG.info('Test the following offload nics - {}'.format(offload_nics))
        # devlink cmd to retrieve switch mode of interface
        devlink_cmd = "sudo devlink dev eswitch show pci/{}"
        # Initialize results list
        result = []
        # Expected result is a list of dicts containing a dict of
        # hypervisor's IP, its offload nics as keys and the value 'true'
        # Example:
        # [{'192.0.160.1': [{'p6p1': 'true'}, {'p6p2': 'true'}]},
        #  {'192.0.160.2': [{'p6p1': 'true'}, {'p6p2': 'true'}]}]
        expected_result = [{ip: [{nic: 'true'} for nic, _ in nics.items()]}
                           for ip, nics in offload_nics.items()]
        for hypervisor, nics in offload_nics.items():
            dev_result = []
            # Check hw-offload config on hypervisor
            hyper_check = \
                'sudo ovs-vsctl get Open_vSwitch . other_config:hw-offload'
            hyper_offload_state = shell_utils.run_command_over_ssh(hypervisor,
                                                                   hyper_check)
            if not hyper_offload_state.strip() == '"true"':
                dev_result.append('No hw-offload on hypervisor')
                result.append({hypervisor: dev_result})
                LOG.info('No hw-offload on hypervisor {}'.format(hypervisor))
                continue
            LOG.info('Hw-offload configured on hyper - {}'.format(hypervisor))
            for nic, nic_options in nics.items():
                dev_query = shell_utils.run_command_over_ssh(
                    hypervisor, devlink_cmd.format(nic_options['bus-info']))
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
        It will also capture traffic in representor port in both
        hypervisors. There should be a single packet por icmp
        reply/request. As soon as offloading is working, tcpdump
        does not show any packet in representor port

        :param test: Test name from the external config file.
        """

        LOG.info('Start test_offload_ovs_flows test.')
        LOG.info('test_offload_ovs_flows create vms')
        # Create servers
        servers, key_pair = self.create_and_verify_resources(test=test,
                                                             num_servers=4)
        # sleep 10 seconds so that flows generated checking provider network
        # connectivity during resource creation are removed. Timeout for flows
        # deletion is 10 seconds
        time.sleep(10)

        cmd_flows = 'sudo ovs-appctl dpctl/dump-flows -m type=offloaded'

        # server[0] will be the server from which ping will be executed to
        # the other servers using all of the different networks they have
        ssh_source = self.get_remote_client(servers[0]['fip'],
                                            username=self.instance_user,
                                            private_key=key_pair[
                                                'private_key'])
        # iterate servers
        for server in servers[1:]:
            # iterate networks
            for provider_network in server['provider_networks']:

                # get network in the server in which ping is being executed
                source_network = \
                    next(item for item in servers[0]['provider_networks'] if
                         item["network_id"] == provider_network["network_id"])

                # pair with the server and network used for ping
                srv_pair = [{'server': servers[0], 'network': source_network},
                            {'server': server, 'network': provider_network}]

                # execute tcpdump in representor port in both hypervisors
                for srv_item in srv_pair:
                    vf_nic = shell_utils.get_vf_from_mac(
                        srv_item['network']['mac_address'],
                        srv_item['server']['hypervisor_ip'])

                    srv_item['tcpdump_file'] = "/tmp/dump_{}.txt".format(
                        vf_nic)
                    tcpdump_cmd = "sudo timeout {} tcpdump -i {} icmp " \
                                  "> {} 2>&1 &". \
                        format(600, vf_nic, srv_item['tcpdump_file'])
                    LOG.info('Executed on {}: {}'.format(
                        srv_item['server']['hypervisor_ip'],
                        tcpdump_cmd))
                    shell_utils.run_command_over_ssh(
                        srv_item['server']['hypervisor_ip'],
                        tcpdump_cmd)

                # continuous ping
                shell_utils.\
                    continuous_ping(srv_pair[1]['network']['ip_address'],
                                    duration=600,
                                    ssh_client_local=ssh_source)
                LOG.info('Run continuous ping from {} to {}'.
                         format(srv_pair[0]['network']['ip_address'],
                                srv_pair[1]['network']['ip_address']))

                # Execute ping for a while, we need several ping
                # requests/replies. Only the first one should be
                # captured by tcpdump
                time.sleep(10)

                for srv_item in srv_pair:
                    # check flows in both hypervisors
                    LOG.info('test_offload_ovs_flows verify flows on '
                             'hypervisor {}'.
                             format(srv_item['server']['hypervisor_ip']))
                    out = shell_utils.run_command_over_ssh(
                        srv_item['server']['hypervisor_ip'], cmd_flows)
                    msg = ('Port with mac address {} is expected to be part '
                           'of offloaded flows')
                    port = self.get_port_from_ip(
                        srv_item['network']['ip_address'])
                    self.assertTrue('capabilities' in port['binding:profile']
                                    and 'switchdev' in
                                    port['binding:profile']['capabilities'],
                                    "port has not 'capabilities'")
                    self.assertIn(port['mac_address'], out,
                                  msg.format(port['mac_address']))
                    self.assertIn('offloaded:yes, dp:tc', out,
                                  'Did not find "offloaded:yes, dp:tc"')

                    # check tcpdump output. Only first packet should be going
                    # through representor port. Once offload is working, there
                    # should be no packet in representor port
                    stop_cmd = '(if pgrep tcpdump; then sudo pkill tcpdump;' \
                               ' fi; file={}; sudo cat $file; sudo rm $file)' \
                               ' 2>&1'.format(srv_item['tcpdump_file'])
                    LOG.info('Executed on {}: {}'.format(
                        server['hypervisor_ip'], stop_cmd))
                    output = shell_utils.run_command_over_ssh(
                        srv_item['server']['hypervisor_ip'], stop_cmd)

                    icmp_requests = output.count('ICMP echo request')
                    icmp_replies = output.count('ICMP echo reply')
                    self.assertTrue(icmp_requests == 1 and icmp_replies == 1,
                                    'There should be a single request/reply '
                                    'in representor port. IP: {}, '
                                    'Requests: {}, Replies: {}'.
                                    format(srv_item['network']['ip_address'],
                                           icmp_requests,
                                           icmp_replies))

                # send stop statistics signal
                shell_utils.stop_continuous_ping(ssh_client_local=ssh_source)
