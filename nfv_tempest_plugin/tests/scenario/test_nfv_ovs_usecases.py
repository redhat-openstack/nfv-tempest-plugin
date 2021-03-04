# Copyright 2020 Red Hat, Inc.
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

from nfv_tempest_plugin.tests.common.discovery import ovs_bond
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config
from tempest.lib import exceptions as lib_exc

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestOvsScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestOvsScenarios, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(TestOvsScenarios, self).setUp()

    def test_ovs_active_backup_bond_connectivity(self,
                                                 test='ovs_bond_connectivity',
                                                 req_type='active-backup'):
        """Test link aggregation for OVS bonds

        During the test, instances will be spawned, ping will be performed on
        network attached to OVS, if ping is successful, will attempt to
        perform a failover on OVS bond, current master should become a slave
        and the opposite.
        After failover, attempt to ping network again.

        In the future we should have async ping running before/during/post
        OVS bond failover.

        :param test: Test name from the config file
        :param req_type: Requested bond type
        """
        self.assertNotEmpty(CONF.nfv_plugin_options.ovs_test_bonds,
                            'No OVS bonds defined in configuration')
        servers, key_pair = \
            self.create_and_verify_resources(test=test)
        # Create OpenStack admin clients
        network_client = self.os_admin.networks_client
        subnet_client = self.os_admin.subnets_client
        # Overcloud username
        overcloud_username = CONF.nfv_plugin_options.overcloud_node_user
        # Overcloud private key
        with open(CONF.nfv_plugin_options.overcloud_node_pkey_file, 'r') as f:
            overcloud_private_key = f.read()
        for server in servers:
            # Initialize helper variables
            ovs_bonds = []
            guest_networks = []
            failover_failed = False
            hypervisor_ip = server['hypervisor_ip']
            # Discover OVS bonds on hypervisor
            ovs_bonds = ovs_bonds.discover(hypervisor_ip)
            for bond in ovs_bonds:
                if bond.type != req_type:
                    ovs_bonds.remove(bond)
                else:
                    for bond_n in CONF.nfv_plugin_options.ovs_bond_under_test:
                        current_bond = \
                            ovs_bond.construct_ovs_bond_tuple_from_node(
                                hypervisor_ip, bond_n, req_type)
                        # Remove current bond object and replace it with an
                        # update tuple
                        ovs_bonds.remove(bond)
                        ovs_bonds.append(current_bond)
            msg = 'No bonds of type {} were found'.format(req_type)
            self.assertNotEmpty(ovs_bond, msg)
            # Construct OVS bonds tuples from node
            # Create SSH client to guest
            guest_ssh = \
                self.get_remote_client(server['fip'],
                                       username=self.instance_user,
                                       private_key=key_pair['private_key'])
            # Create SSH client to hypervisor hosting the guest
            hypervisor_ssh = \
                self.get_remote_client(hypervisor_ip,
                                       username=overcloud_username,
                                       private_key=overcloud_private_key)
            # Iterate over fetched bonds
            for bond in ovs_bonds:
                # If bond is present on hypervisor
                if bond.node == hypervisor_ip:
                    # Initialize helper variables
                    master_interface = bond.master_interface
                    bond_interface = bond.interface
                    server_ports = self.os_admin.ports_client.list_ports(
                        device_id=server['id'])['ports']
                    for port in server_ports:
                        # Filter attached ports based on a key
                        if 'bridge_name' in port['binding:vif_details']:
                            guest_networks.append(port['network_id'])
                    # Iterate over supplied guest networks attached to bond
                    for net in guest_networks:
                        net_query = (network_client.list_networks(id=net)
                                     ['networks'])
                        msg = "Failed to discover network '{}'".format(net)
                        self.assertNotEmpty(net_query, msg)
                        net_obj = net_query[0]
                        subnet_obj = (subnet_client.list_subnets(
                                      network_id=net_obj['id'])['subnets'][0])
                        subnet_gateway = subnet_obj['gateway_ip']
                        LOG.info("Default gateway for network '{n}' is set "
                                 "to '{g}'".format(n=net, g=subnet_gateway))
                        # Attempt to ping network's default gateway
                        try:
                            guest_ssh.icmp_check(subnet_gateway)
                        except lib_exc.SSHExecCommandFailed:
                            msg = ("Failed to ping networks '{n}' default "
                                   "gateway '{g}'".format(n=net,
                                                          g=subnet_gateway))
                            raise lib_exc.SSHExecCommandFailed(msg)
                        LOG.info("Initial ping is successful, will attempt "
                                 "to perform failover for bond '{b}' on "
                                 "hypervisor '{h}'".format(b=bond_interface,
                                                           h=hypervisor_ip))
                        # Attempt to bring down master interface - failover
                        try:
                            hypervisor_ssh.exec_command(bond.ifdown_cmd)
                        except lib_exc.SSHExecCommandFailed:
                            msg = ("Failed to bring down interface '{i}' "
                                   "in bond '{b}' on hypervisor {h}"
                                   .format(i=master_interface,
                                           b=bond_interface,
                                           h=hypervisor_ip))
                            raise lib_exc.SSHExecCommandFailed(msg)
                        LOG.info("Performed failover in bond '{b}', "
                                 "interface '{i}' is no longer master on "
                                 "hypervisor '{h}'".format(b=bond_interface,
                                                           i=master_interface,
                                                           h=hypervisor_ip))
                        LOG.info("Will attempt to ping default gateway "
                                 "'{g}' on network '{n}'"
                                 .format(g=subnet_gateway, n=net))
                        # Attempt to ping network's default gateway
                        try:
                            guest_ssh.icmp_check(subnet_gateway)
                        except lib_exc.SSHExecCommandFailed:
                            LOG.info("Failed to ping networks '{n}' default "
                                     "gateway '{g}' post failover"
                                     .format(n=net, g=subnet_gateway))
                            failover_failed = True
                        finally:
                            # Attempt to bring up master interface
                            try:
                                hypervisor_ssh.exec_command(bond.ifup_cmd)
                            except lib_exc.SSHExecCommandFailed:
                                msg = ("Failed to bring up interface '{i} "
                                       "in bond '{b}' on hypervisor '{h}' ,"
                                       "check hypervisor for more details"
                                       .format(i=master_interface,
                                               b=bond_interface,
                                               h=hypervisor_ip))
                                raise lib_exc.SSHExecCommandFailed(msg)
                        self.assertFalse(failover_failed)
                        LOG.info("Failover scenario is successful for bond "
                                 "'{b}' on hypervisor '{h}'"
                                 .format(b=bond_interface, h=hypervisor_ip))
        LOG.info('The {} test passed.'.format(test))
