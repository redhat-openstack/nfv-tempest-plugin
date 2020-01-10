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

import re
import time

from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestSriovScenarios(base_test.BaseTest):
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

    def test_sriov_max_qos(self, test='max_qos'):
        """Test SRIOV MAX QoS functionality

        The test require [nfv_plugin_options ]
        use_neutron_api_v2 = true in tempest.config.
        Test also requires QoS neutron settings.
        The test deploy 3 vms. one iperf server receive traffic from
        two iperf clients, with max_qos defined run against iperf server.
        The test search for Traffic per second and compare against ports
        seetings
        """
        LOG.info('Start SRIOV Max QoS test.')
        kwargs = {}
        max_burst = 4000000
        max_kbps_1 = 4000000
        max_kbps_2 = 9000000
        qos1_rules = {'max_kbps': str(max_kbps_1),
                      'max_burst_kbps': str(max_burst)}
        qos2_rules = {'max_kbps': str(max_kbps_2),
                      'max_burst_kbps': str(max_burst)}
        kwargs['ignore_ext_config'] = True
        kwargs['flavor'] = self.flavor_ref
        servers, key_pair = self.create_and_verify_resources(
            test=test, num_servers=3, **kwargs)
        if len(servers) != 3:
            raise ValueError('The test requires 3 instances.')

        # Max QoS configuration to server ports
        qos1 = self.create_qos_policy_with_rules(use_default=False,
                                                 **qos1_rules)
        qos2 = self.create_qos_policy_with_rules(use_default=False,
                                                 **qos2_rules)
        # Find machnes direct ports
        ports = self.os_admin.\
            ports_client.list_ports(device_id=servers[2]['id'])
        port_id, ip_addr = \
            shell_utils.find_vm_interface(ports, vnic_type='direct')
        ports = self.os_admin.\
            ports_client.list_ports(device_id=servers[0]['id'])
        port_id1, ip_addr1 = \
            shell_utils.find_vm_interface(ports, vnic_type='direct')
        ports = self.os_admin.\
            ports_client.list_ports(device_id=servers[1]['id'])
        port_id2, ip_addr2 = \
            shell_utils.find_vm_interface(ports, vnic_type='direct')
        # Set pors with QoS
        LOG.info('Send iperf traffic from Server2...')
        self.update_port(port_id1,
                         **{'qos_policy_id': qos1['id']})
        self.update_port(port_id2,
                         **{'qos_policy_id': qos2['id']})

        LOG.info('Run iperf server on server3...')
        ssh_dest = self.get_remote_client(servers[2]['fip'],
                                          username=self.instance_user,
                                          private_key=key_pair[
                                          'private_key'])
        server_command = "sudo yum install iperf -y; "
        log_5102 = "/tmp/listen-5102.txt"
        log_5101 = "/tmp/listen-5101.txt"
        server_command += \
            "(nohup iperf -s -B {} -p 5102 -i 10 >> {} 2>&1)& ".format(
                ip_addr, log_5102)
        server_command += \
            "(nohup iperf -s -B {} -p 5101 -i 10 >> {} 2>&1)& ".format(
                ip_addr, log_5101)
        LOG.info('Receive iperf traffic from Server3...')
        ssh_dest.exec_command(server_command)

        ssh_source1 = self.\
            get_remote_client(servers[0]['fip'],
                              username=self.instance_user,
                              private_key=key_pair['private_key'])
        LOG.info('Send iperf traffic from Server1...')
        client_command = "sudo yum install iperf -y; "
        client_command += \
            "iperf -c {} -T s1 -p {} -t 60".format(ip_addr, '5101')
        ssh_source1.exec_command(client_command)

        ssh_source2 = self.\
            get_remote_client(servers[1]['fip'],
                              username=self.instance_user,
                              private_key=key_pair['private_key'])
        LOG.info('Send iperf traffic from Server2...')
        client_command = "sudo yum install iperf -y; "
        client_command += \
            "iperf -c {} -T s2 -p {} -t 60".format(ip_addr, '5102')

        ssh_source2.exec_command(client_command)
        # Run grep command over iperf server to verify BW is OK
        LOG.info('Collect iperf logs from iperf server, server3...')
        command = r"cat {} | while read line ;do  "
        command += r"if [[ \"$line\" =~ [[:space:]]"
        command += r"([0-9]\.[0-9]{2})[[:space:]]Gbits ]]; "
        command += r"then echo \"${BASH_REMATCH[1]}\"; fi; done| sort| uniq"
        # Recive result with number
        out_testing = ssh_dest.exec_command(command.replace('{}', log_5101))
        # Assert result
        iperf_rep = \
            [i for i in (out_testing.encode('utf8')).split("\n") if i != '']
        self.assertNotEmpty(
            iperf_rep,
            "Please check QoS definitions, iperf result for in file {}"
            " is empty or low".format(log_5101))
        for rep in iperf_rep:
            dev = abs(float(rep.replace('\"', ''))
                      * 10**6 - max_kbps_1) / float(max_kbps_1)
            self.assertLess(dev, 0.03, "report is greater than 0.03")
        out_testing = ssh_dest.exec_command(command.replace('{}', log_5102))
        # Assert result
        iperf_rep = \
            [i for i in (out_testing.encode('utf8')).split("\n") if i != '']
        self.assertNotEmpty(
            iperf_rep,
            "Please check QoS definitions, iperf result for in file {}"
            " is empty or low".format(log_5102))
        for rep in iperf_rep:
            dev = abs(float(rep.replace('\"', ''))
                      * 10**6 - max_kbps_2) / float(max_kbps_2)
            self.assertLess(dev, 0.03, "report is greater than 0.03")
