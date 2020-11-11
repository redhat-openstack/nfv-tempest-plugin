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

import json
import re
import six
import time


from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from nfv_tempest_plugin.tests.scenario.qos_manager import QoSManagerMixin
from oslo_log import log as logging
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestSriovScenarios(base_test.BaseTest, QoSManagerMixin):
    def __init__(self, *args, **kwargs):
        super(TestSriovScenarios, self).__init__(*args, **kwargs)

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestSriovScenarios, self).setUp()
        # pre setup creations and checks read from

    def test_sriov_trusted_vfs(self, test='trustedvfs'):
        """Verify trusted virtual functions

        The test search 'trust on' configuration in the instance interfaces.
        """
        trusted_vfs_mac_addresses = []
        servers, key_pair = self.create_and_verify_resources(test=test)
        LOG.info('List ports and search for "trusted" in binding profile.')
        ports = self.ports_client.list_ports(device_id=servers[0]['id'])
        for port in ports['ports']:
            if 'trusted' in port['binding:profile'] and \
                    port['binding:profile']['trusted']:
                trusted_vfs_mac_addresses.append(port['mac_address'])
        self.assertNotEmpty(trusted_vfs_mac_addresses,
                            "No trusted VFs are attached to server")
        LOG.info('Test the "trust on" interface on the hypervisor.')
        result = shell_utils.\
            get_interfaces_from_overcloud_node(servers[0]['hypervisor_ip'])
        for mac_address in trusted_vfs_mac_addresses:
            re_string = r'.*{}.*'.format(mac_address)
            line = re.search(re_string, result)
            # Failed to locate MAC address on hypervisor
            if not line:
                raise ValueError("Failed to locate interface with MAC "
                                 "'{}' on hypervisor".format(mac_address))
            line = line.group(0)
            if mac_address in line:
                self.assertIn('trust on', line)
        LOG.info('The {} test passed.'.format(test))
        return True

    def test_sriov_double_tagging(self, test='double_tagging'):
        """Test SRIOV double tagging functionality

        The test require resource creator to setup initial test resources.
        Refer to the documentation regarding the test configuration.
        Note! - Both of the vlans should be allowed on the switch ports.
        """
        if self.external_resources_data is None:
            raise ValueError('External resource data is required for the test')

        LOG.info('Start SRIOV double tagging test.')
        servers, key_pair = self.create_and_verify_resources(test=test)
        if len(servers) != 4:
            raise ValueError('The test requires 4 instances.')

        if 'iface_vlan' and 'test_vlan' in \
                self.test_setup_dict[test]['vlan_config']:
            iface_vlan = \
                self.test_setup_dict[test]['vlan_config']['iface_vlan']
            test_vlan = self.test_setup_dict[test]['vlan_config']['test_vlan']
            LOG.info('Set test vlans {} and {} for the test'.format(iface_vlan,
                                                                    test_vlan))
        else:
            raise ValueError('The "iface_vlan" and "test_vlan" is missing from'
                             'the test config. Refer to the documentation. In '
                             'addition, make sure the "iface_vlan" and "test_v'
                             'lan" allowed in the switch to continue the test')

        trigger = None
        # Base vlan is the deployment vlan (neutron) and required by PF iface.
        base_vlan = ''
        for num, srv in enumerate(servers):
            srv_ports = self.ports_client.list_ports(
                device_id=srv['id'])['ports']
            for port in srv_ports:
                if port['binding:vnic_type'] in {'direct', 'direct-physical'}:
                    srv['test_port_type'] = port['binding:vnic_type']
                    srv['test_mac_addr'] = port['mac_address']
                    srv['test_ip_addr'] = '10.10.10.1{}'.format(num)

            if srv['test_port_type'] == 'direct-physical':
                srv['test_name'] = 'pf1'
            else:
                srv['test_name'] = 'vf{}'.format(num + 1)

            if trigger is None:
                cmd = "sudo ip link | awk -F ',' '/{}/ {{print $2}}' " \
                      "| tr -dc '0-9'".format(srv['test_mac_addr'])
                base_vlan = shell_utils.run_command_over_ssh(
                    srv['hypervisor_ip'], cmd)
                trigger = 'stop'

            vf_config = 'sudo python {script_path}/packages_deploy.py ' \
                        '--pip-packages scapy; sudo python ' \
                        '{script_path}/post_net_bootstrap.py --add-iface ' \
                        '--port-type {port_type} --mac {mac} --vlan ' \
                        '{iface_vlan} --addr {addr}/24'
            pf_config = vf_config + ' --base-vlan {base_vlan}'
            vf_config = vf_config.format(script_path=self.nfv_scripts_path,
                                         port_type='vf',
                                         mac=srv['test_mac_addr'],
                                         addr=srv['test_ip_addr'],
                                         iface_vlan=iface_vlan)
            pf_config = pf_config.format(script_path=self.nfv_scripts_path,
                                         port_type='pf',
                                         mac=srv['test_mac_addr'],
                                         addr=srv['test_ip_addr'],
                                         iface_vlan=iface_vlan,
                                         base_vlan=base_vlan)
            LOG.info('Create and configure virtual interface for '
                     '{}'.format(srv['test_name']))
            ssh_source = self.get_remote_client(srv['fip'],
                                                username=self.instance_user,
                                                private_key=key_pair[
                                                    'private_key'])
            output = ssh_source.exec_command(pf_config if
                                             srv['test_port_type']
                                             == 'direct-physical'
                                             else vf_config)
            srv['test_nic'] = output.split('\n')[-4].split(' ')[-1]

        vf1 = servers[0]

        scapy_sniff = 'sudo python {script_path}/scapy_traffic.py --sniff ' \
                      '--keep-sniff -i {iface} -c 5 > /dev/null 2>&1 &'
        scapy_icmp = 'sudo python {script_path}/scapy_traffic.py ' \
                     '--{pkt_type} -i {iface} -c 5 --src-mac {src_mac} ' \
                     '--src-ip {src_ip} --dst-mac {dst_mac} --dst-ip ' \
                     '{dst_ip} --iface-vlan {iface_vlan} --test-vlan ' \
                     '{test_vlan}'
        scapy_mpls = scapy_icmp + ' --raw-msg {raw_msg}'

        send_traffic_cmd = ''
        LOG.info('Start to sniff for ICMP traffic')
        for sniffer in servers:
            if sniffer['test_name'] in ['vf2', 'vf3', 'pf1']:
                ssh_source = self.get_remote_client(
                    sniffer['fip'], username=self.instance_user,
                    private_key=key_pair['private_key'])
                LOG.info('Start sniffing on {}'.format(sniffer['test_name']))
                ssh_source.exec_command(scapy_sniff.format(
                    iface=sniffer['test_nic']))
                s1 = scapy_icmp.format(script_path=self.nfv_scripts_path,
                                       pkt_type='icmp', iface=vf1['test_nic'],
                                       src_mac=vf1['test_mac_addr'],
                                       src_ip=vf1['test_ip_addr'],
                                       dst_mac=sniffer['test_mac_addr'],
                                       dst_ip=sniffer['test_ip_addr'],
                                       iface_vlan=iface_vlan,
                                       test_vlan=test_vlan)
                s2 = scapy_mpls.format(script_path=self.nfv_scripts_path,
                                       pkt_type='mpls', iface=vf1['test_nic'],
                                       src_mac=vf1['test_mac_addr'],
                                       src_ip=vf1['test_ip_addr'],
                                       dst_mac=sniffer['test_mac_addr'],
                                       dst_ip=sniffer['test_ip_addr'],
                                       iface_vlan=iface_vlan,
                                       test_vlan=test_vlan, raw_msg='testtest')
                send_traffic_cmd += '{}; {}; '.format(s1, s2)
        LOG.info('Send ICMP traffic')
        ssh_source = self.get_remote_client(vf1['fip'],
                                            username=self.instance_user,
                                            private_key=key_pair[
                                                'private_key'])
        LOG.info('Set scapy packets\n{}'.format(send_traffic_cmd))
        ssh_source.exec_command(send_traffic_cmd)

        LOG.info('Check for the results')
        test_results = []
        for sniffer in servers:
            if sniffer['test_name'] in ['vf2', 'vf3', 'pf1']:
                cmd = 'grep output /tmp/scapy_traffic.log | grep -o -e ' \
                      '"{[^}]*}" | tail -n2 || true'
                ssh_source = self.get_remote_client(
                    sniffer['fip'], username=self.instance_user,
                    private_key=key_pair['private_key'])
                output = ssh_source.exec_command(cmd)
                if output:
                    output = output.splitlines()
                    for option in output:
                        opt = eval(option)
                        if opt['pkt_type'] not in ['icmp', 'mpls']:
                            test_results.append(
                                '{} did not catch ICMP or MPLS '
                                'traffic'.format(sniffer['test_name']))
                        if opt['pkt_count'] != 5:
                            test_results.append(
                                '{} catch less packets than '
                                'expected'.format(sniffer['test_name']))
                else:
                    test_results.append('Output failed for '
                                        '{}'.format(sniffer['test_name']))

        for srv in servers:
            vf_remove = 'sudo python {script_path}/post_net_bootstrap.py ' \
                        '--del-iface --port-type vf --mac {mac} --vlan ' \
                        '{iface_vlan}'\
                .format(script_path=self.nfv_scripts_path,
                        mac=srv['test_mac_addr'], iface_vlan=iface_vlan)
            pf_remove = 'sudo python {script_path}/post_net_bootstrap.py ' \
                        '--del-iface --port-type pf --mac {mac} --base-vlan ' \
                        '{base_vlan}'.format(script_path=self.nfv_scripts_path,
                                             mac=srv['test_mac_addr'],
                                             base_vlan=base_vlan)
            remove_log_file = '; sudo rm -f /tmp/scapy_traffic.log'
            vf_remove += remove_log_file
            pf_remove += remove_log_file
            ssh_source = self.get_remote_client(srv['fip'],
                                                username=self.instance_user,
                                                private_key=key_pair[
                                                    'private_key'])
            ssh_source.exec_command(pf_remove if
                                    srv['test_port_type']
                                    == 'direct-physical' else vf_remove)

        self.assertEmpty(test_results, test_results)

    def test_guests_with_min_bw(self, test='sriov_min_bw_qos'):
        """Test SR-IOV minimum bandwith (Nova)

        Spawn a guest with a minimum already applied to port
        """
        # Create servers
        qos_rules = {}
        for rule in self.test_setup_dict[test]['qos_rules']:
            qos_rules.update(rule)
        self.test_setup_dict[test]
        self.create_qos_policy_with_rules(**qos_rules)
        resource_args = {'set_qos': True}
        servers, key_pair = self.create_and_verify_resources(test=test,
                                                             **resource_args)
        # Iterate over servers
        for server in servers:
            self.check_qos_attached_to_guest(server,
                                             min_bw=True)

    def test_guests_set_min_qos(self, test='sriov_min_bw_qos'):
        """Test SR-IOV minimum QoS

        Spawn a guest and set (neutron) minimum QoS to port already up
        """
        qos_rules = {}
        for rule in self.test_setup_dict[test]['qos_rules']:
            qos_rules.update(rule)
        self.create_qos_policy_with_rules(**qos_rules)
        # Create servers
        resource_args = {'set_qos': False}
        servers, key_pair = self.create_and_verify_resources(test=test,
                                                             **resource_args)
        # search for min_qos port
        min_qos_port = ''
        for port in self.os_admin.ports_client.list_ports(
                device_id=self.servers[0]['id'])['ports']:
            if 'min-qos' in port['name']:
                min_qos_port = port['id']
        # Update QoS of the port
        self.update_port(min_qos_port,
                         **{'qos_policy_id': self.qos_policy_groups['id']})
        # Wait the qos_policy update
        msg = "qos policy was not added to port {}".join(min_qos_port)
        time.sleep(5)
        client = self.os_admin.ports_client
        self.assertIsNotNone(
            client.show_port(min_qos_port)['port']['qos_policy_id'],
            msg)
        for server in servers:
            self.check_qos_attached_to_guest(server,
                                             min_bw=True)

    def test_sriov_free_resource(self, test='sriov_reset_resources'):
        """Test_sriov_free_resources

        The method checks if sriov nics are released after guest/port deletion.
        Verification is run before test starts and at the end
        """
        # Check resources are free in computes
        self.test_setup_dict['sriov_reset_resources'] = \
            {'flavor-id': self.flavor_ref, 'router': True, 'aggregate': None}
        default_port_type = {'ports_filter': 'external,direct'}
        resource_args = {'num_servers': 4,
                         'srv_details': {0: default_port_type,
                                         1: default_port_type,
                                         2: default_port_type,
                                         3: default_port_type}}
        # Set test parameters
        kw_args = {}
        osp_release = self.get_osp_release()
        # Starting from OSP13, installation is containerized
        kw_args['command'] = "sudo ip link show"
        kw_args['file_path'] = \
            '/var/lib/config-data/nova_libvirt/etc/nova/nova.conf'
        if osp_release < 13:
            kw_args['file_path'] = '/etc/nova/nova.conf'
        kw_args['search_param'] = \
            {'section': 'pci', 'value': 'passthrough_whitelist'}
        """ Regexp search VF interfaces with neutron MAC prefix,
        [Cr] is for catching the following options: MAC|link/ether for
        different OS versions """
        kw_args['filter_regexp'] = \
            r"\s+vf.*[Cr]\sfa:16:3e:[a-fA-F0-9:]{2}.*"
        kw_args['servers_ips'] = self.\
            _get_hypervisor_ip_from_undercloud(shell='/home/stack/stackrc')
        kw_args['multi_key_values'] = True
        # Verify empty machines are reset back from previous tests
        result = shell_utils. \
            run_hypervisor_command_build_from_config(**kw_args)
        # Iterate regexp result if found some thing fail test
        msg = "Parameters not in [] required state \n {}".format(result)
        for ihost in result.keys():
            assert len(result[ihost]) == 0, msg.replace("[]", ihost)
        # Create resources:
        self.create_and_verify_resources(test=test, **resource_args)
        # Check resources are free in computes
        for server in self.servers:
            ports_list = (
                self.os_admin.ports_client.list_ports(
                    device_id=server['id']))['ports']
            delete_ports = [x['id'] for x in ports_list]
            # Delete computes and ports
            self.os_primary.servers_client.delete_server(server['id'])
            for port in delete_ports:
                self.os_admin.ports_client.delete_port(port)
        # Verify empty machines are reset back after tests
        result = shell_utils. \
            run_hypervisor_command_build_from_config(**kw_args)
        # Iterate regexp result if found some thing fail test
        for ihost in result.keys():
            assert len(result[ihost]) == 0, msg.replace("[]", ihost)

    def test_sriov_max_qos(self, test='max_qos'):
        """Test SRIOV MAX QoS functionality

        The test require [nfv_plugin_options ]
        use_neutron_api_v2 = true in tempest.config.
        Test also requires QoS neutron settings.
        The test deploy 3 vms. one iperf server receive traffic from
        two iperf clients, with max_qos defined run against iperf server.
        The test search for Traffic per second and compare against ports
        seeings
        """

        LOG.info('Start SRIOV Max QoS test.')
        kwargs = {}
        qos_rules = \
            json.loads(CONF.nfv_plugin_options.max_qos_rules)
        qos_rules_list = [x for x in qos_rules]
        servers, key_pair = self.create_and_verify_resources(
            test=test, num_servers=3, **kwargs)
        if len(servers) != 3:
            raise ValueError('The test requires 3 instances.')
        # Max QoS configuration to server ports
        LOG.info('Create QoS Policies...')
        qos_policies = [self.create_qos_policy_with_rules(
            use_default=False, **i) for i in qos_rules_list]
        self.run_iperf_test(qos_policies, servers, key_pair)
        self.collect_iperf_results(qos_rules_list, servers, key_pair)

    def test_sriov_min_qos(self, test='min_qos'):
        """Test SRIOV MIN QoS functionality

        SUPPORTED: Mellanox NICS only
        The test require [nfv_plugin_options ]
        use_neutron_api_v2 = true in tempest.config.
        Test also requires QoS neutron settings.
        The test deploy 3 vms. one iperf server receive traffic from
        two iperf clients, with min_qos defined run against iperf server.
        The test search for Traffic per second and compare against ports
        seeings
        """

        LOG.info('Start SRIOV Min QoS test, search for Mellanox nics')
        # Check setup contains Mellanox nics.
        kw_args = dict()
        kw_args['command'] = r"sudo lshw -class network -short | grep "
        kw_args['file_path'] = \
            '/var/lib/config-data/nova_libvirt/etc/nova/nova.conf'
        kw_args['search_param'] = \
            {'section': 'pci', 'value': 'passthrough_whitelist'}
        """ Regexp search Mellanox connect-x """
        kw_args['filter_regexp'] = \
            r".*\[ConnectX\-5\].*"
        kw_args['servers_ips'] = self. \
            _get_hypervisor_ip_from_undercloud(shell='/home/stack/stackrc')
        kw_args['multi_key_values'] = True
        LOG.info('Start SRIOV Min QoS test.')
        result = shell_utils. \
            run_hypervisor_command_build_from_config(**kw_args)
        msg = "no nics supporting sriov min bw"
        self.assertTrue(
            len(result) > 0, msg)
        qos_rules = \
            json.loads(CONF.nfv_plugin_options.min_qos_rules)
        qos_rules_list = [x for x in qos_rules]
        LOG.info('SRIOV Min QoS test, '
                 'learn provider network attached to device.')
        # Assuming both computes have the same hw
        # searching for physnet of Mellanox
        devices = \
            [re.split(r'\s+', i)[1] for i in six.next(six.itervalues(result))]
        pci_list = shell_utils.\
            get_value_from_ini_config(six.next(six.iterkeys(result)),
                                      kw_args['file_path'],
                                      kw_args['search_param']['section'],
                                      kw_args['search_param']['value'],
                                      kw_args['multi_key_values'])
        pci_list = '[' + pci_list + ']'
        json_list = json.loads(pci_list.replace("\n", ","))
        net_name = [pci_item['physical_network'] for pci_item in json_list
                    if pci_item['devname'] == devices[0]]

        LOG.info('SRIOV Min QoS test, create test vms.')
        # Test deploy 3 VMS on singlr hypervisor.
        hyper = self.hypervisor_client.list_hypervisors()['hypervisors']

        kw_test = \
            {'availability_zone': {'hyper_hosts': [hyper[0]
                                                   ['hypervisor_hostname']]}}
        default_port_type = \
            {'ports_filter': "{}:{}".format('external,direct', net_name[0])}
        kw_test['num_servers'] = 3
        kw_test['srv_details'] = {0: default_port_type,
                                  1: default_port_type,
                                  2: default_port_type}
        servers, key_pair = self.create_and_verify_resources(
            test=test, **kw_test)
        if len(servers) != 3:
            raise ValueError('The test requires 3 instances.')
        # Min QoS configuration to server ports
        LOG.info('Create QoS Policies...')
        qos_policies = [self.create_qos_policy_with_rules(
            use_default=True, **i) for i in qos_rules_list]
        LOG.info('SRIOV Min QoS test, run test.')
        self.run_iperf_test(qos_policies, servers, key_pair)
        LOG.info('SRIOV Min QoS test, check test result.')
        self.collect_iperf_results(qos_rules_list, servers, key_pair)
