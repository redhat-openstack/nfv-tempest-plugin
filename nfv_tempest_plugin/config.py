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
import os
from oslo_config import cfg


class HypervisorGroupUtils(object):
    @staticmethod
    def get_default_personality():
        plugin_dir = os.path.dirname(os.path.realpath(__file__))
        tests_scripts_dir = plugin_dir + "/tests/scenario/tests_scripts"
        default_script = tests_scripts_dir + "/custom_net_config.py"
        default_personality = []
        default_guest_path = "/tmp/custom_net_config.py"
        default_personality.append({"client_source": default_script,
                                    "guest_destination": default_guest_path})
        default_personality = json.dumps(default_personality)
        return default_personality

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
    cfg.StrOpt('transfer_files',
               default=HypervisorGroupUtils.get_default_personality(),
               help=("List of dictionaries contanining paths and "
                     "destinations of files to be tranfered from "
                     "client to guest")),
]
