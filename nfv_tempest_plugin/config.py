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

from oslo_config import cfg

hypervisor_group = cfg.OptGroup(name="hypervisor",
                                title="Hypervisor params")

HypervisorGroup = [
    cfg.StrOpt('user',
               default='heat-admin',
               help="SSH login user"),
    cfg.StrOpt('password',
               default=None,
               help="SSH login password"),
    cfg.StrOpt('private_key_file',
               default='/home/stack/.ssh/id_rsa',
               help="Private key string for imported key for ssh user"),
    cfg.StrOpt('external_config_file',
               default=None,
               help="The path to yml file for additional configurations"),
]
