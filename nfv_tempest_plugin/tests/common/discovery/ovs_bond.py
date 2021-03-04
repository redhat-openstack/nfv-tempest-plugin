# Copyright 2021 Red Hat, Inc.
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

from collections import namedtuple
from nfv_tempest_plugin.tests.common import shell_utils
from oslo_log import log
from tempest import config

CONF = config.CONF
LOG = log.getLogger('{} [-] nfv_plugin_test'.format(__name__))


def discover(node):
    """construct_ovs_bonds

    Queries node and returns all Open vSwitch bonds present on node.
    :param hypervisor: node IP address to fetch info from
    :returns ovs_bonds: list of Open vSwitch bonds
    """
    # Initialize variables
    ovs_bonds = []
    ovs_bond_tuple = namedtuple('OVS_bond', [
        'name',
        'type'
    ])
    check_bonds_cmd = ('sudo ovs-appctl bond/list | sed \'1d\''
                       '| awk \'{print $1","$2}\'')
    output_list = \
        shell_utils.run_command_over_ssh(node,
                                         check_bonds_cmd).split('\n')
    # Removing last element from list which is always empty
    for line in output_list[:-1]:
        bond_name, bond_type = line.split(',')
        ovs_bond = ovs_bond_tuple(bond_name, bond_type)
        ovs_bonds.append(ovs_bond)
        LOG.info("Located bond '{n}' of type '{t}' on node '{no}'"
                 .format(n=bond_name, t=bond_type, no=node))
    LOG.info("Discovered {a} bonds on node '{n}'"
             .format(a=len(ovs_bonds), n=node))
    return ovs_bonds


def construct_ovs_bond_tuple_from_node(node, bond_name,
                                       requested_bond_type):
    """construct_ovs_bond_tuple_from_hypervsior

    Queries node and constructs a namedtuple object
    The namedtuple object stores information and commands associated to
    OVS bond.
    Currently only supports 'active-backup' bond.
    :param node: node IP address to fetch info from
    :param bond_name: bond name to lookup
    :param requested_bond_type: bond type to lookup
    :returns ovs_bond: namedtuple of OVS bond query
    """
    bond = namedtuple('Bond', [
        'node',
        'interface',
        'type',
        'master_interface',
        'ovs_bridge',
        'ifup_cmd',
        'ifdown_cmd'
    ])
    check_bond_cmd = 'sudo ovs-appctl bond/show {}'
    bond_mode_re_filter = r'bond_mode:\s+.*'
    bond_mode_re_sub_filter = r'bond_mode:\s+(.*)'
    # Query bond interface on node
    out = shell_utils.run_command_over_ssh(node,
                                           check_bond_cmd.format(bond_name))
    re_result = re.search(bond_mode_re_filter, out)
    msg = "Could not find bonding mode from bond query output"
    assert re_result is not None, msg
    re_bond_output = re_result.group(0)
    bond_mode = re.sub(bond_mode_re_sub_filter, r'\1',
                       re_bond_output)
    if bond_mode == requested_bond_type:
        ovs_bond = None
        LOG.info("Bond '{b}' is set to mode '{m}'"
                 .format(b=bond_name, m=bond_mode))
        if bond_mode == 'active-backup':
            re_result = re.search(r'active slave mac:\s+.*', out)
            re_bond_output = re_result.group(0)
            bond_master = re.sub(r'active slave mac:\s+.*\((.*)\)',
                                 r'\1', re_bond_output)
            LOG.info("NIC '{m}' is set as master NIC in bond '{b}' on "
                     "node '{n}'".format(m=bond_master,
                                         b=bond_name,
                                         n=node))
            cmd = 'sudo ovs-vsctl port-to-br {}'
            # Fetch OVS general info
            ovs_bridge = \
                shell_utils.run_command_over_ssh(node,
                                                 cmd.format(bond_name))
            ovs_bridge = ovs_bridge.replace('\n', '')
            # Construct interface up/down commands
            bond_if_up_cmd = 'sudo ovs-ofctl mod-port {b} {i} up'
            bond_if_down_cmd = 'sudo ovs-ofctl mod-port {b} {i} down'
            # Apply required variables for interface commands
            bond_if_up_cmd = bond_if_up_cmd.format(b=ovs_bridge,
                                                   i=bond_master)
            bond_if_down_cmd = bond_if_down_cmd.format(b=ovs_bridge,
                                                       i=bond_master)
            # Initialize a namedtuple of current bond
            ovs_bond = bond(node, bond_name, bond_mode,
                            bond_master, ovs_bridge,
                            bond_if_up_cmd,
                            bond_if_down_cmd)
        else:
            LOG.info("Bond type {m} is not supported'"
                     .format(m=bond_mode))
    else:
        LOG.info("Bond '{b}' is not of requested type '{m}'"
                 .format(b=bond_name, m=bond_mode))
    return ovs_bond
