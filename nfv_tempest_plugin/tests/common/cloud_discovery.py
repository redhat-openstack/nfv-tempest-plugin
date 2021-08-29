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

from nfv_tempest_plugin.services.os_clients import OsClients
from oslo_log import log as logging

LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))
os_client = OsClients()
undercloud_heat_client = os_client.undercloud_heatclient
undercloud_nova_client = os_client.novaclient_undercloud


def discover_stacks():
    """Discover all viewable stacks

    Returns a list of discovered stacks
    """
    stacks = []
    # Append stacks present in undercloud to a list
    [stacks.append(s)for s in os_client.undercloud_heatclient.stacks.list()]
    if not stacks:
        raise ValueError('Failed to discover stacks in undercloud')
    LOG.info('Located {} stacks in undercloud deployment'.format(len(stacks)))
    return stacks


def discover_tripleo_services():
    """Discover heat OS::TripleO::Services per stack

    Returns a list of stacks with their TripleO services
    """
    stack_tripleo_services = []
    stacks = discover_stacks()
    if stacks:
        for stack in stacks:
            # Retrieve all TripleO services in stack
            services = list(undercloud_heat_client.stacks.output_show
                            (stack_id=stack.id, output_key='EnabledServices')
                            ['output']['output_value']  .values())[0]
            help_dict = {
                'id': stack.id,
                'name': stack.stack_name,
                'tripleo_services': services
            }
            stack_tripleo_services.append(help_dict)
    return stack_tripleo_services


def discover_nodes_in_stack(stack_id=None):
    """Discover nodes present in stack

    :param stack_id: Stack's ID to query

    Returns a list of nodes
    """
    servers = []
    # Locate all server IDs from stack
    srv = list(undercloud_heat_client.stacks.output_show
               (stack_id=stack_id, output_key='ServerIdData')['output']
               ['output_value']['server_ids'].values())[0]
    for s in srv:
        server = undercloud_nova_client.servers.get(server=s)
        help_dict = {
            'id': s,
            'name': server.name,
            'ip': list(server.networks.values())[0][0]
        }
        servers.append(help_dict)
    return servers
