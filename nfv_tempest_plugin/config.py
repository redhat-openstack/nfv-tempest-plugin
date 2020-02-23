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

from oslo_config import cfg

nfv_plugin_options = cfg.OptGroup(name="nfv_plugin_options",
                                  title="NFV plugin params")

NfvPluginOptions = [
    cfg.StrOpt('overcloud_node_user',
               default='heat-admin',
               help="SSH user for overcloud node - controller/compute"),
    cfg.StrOpt('overcloud_node_pass',
               default=None,
               help="SSH password for overcloud node - controller/compute"),
    cfg.StrOpt('overcloud_node_pkey_file',
               default='/home/stack/.ssh/id_rsa',
               help="SSH private key path for overcloud node - "
                    "controller/compute"),
    cfg.StrOpt("instance_user",
               default="cloud-user",
               help="SSH user for the guest instance"),
    cfg.StrOpt("instance_pass",
               default="password",
               help="SSH password for the guest instance"),
    cfg.StrOpt('external_config_file',
               default=None,
               help="The path to yml file for additional configurations"),
    cfg.StrOpt('transfer_files_src',
               default='tests_scripts',
               help="Relative directory path that contains the test scripts"),
    cfg.StrOpt('transfer_files_dest',
               default='/usr/local/bin/nfv_scripts/',
               help="The default location of nfv test scripts"),
    cfg.StrOpt('external_resources_output_file',
               default='/home/stack/resources_output_file.yml',
               help="The path to the file output of the created resources"),
    cfg.StrOpt('quota_cores',
               default=40,
               help="The numbers of cpu cores for the tenant use"),
    cfg.StrOpt('quota_ram',
               default=81920,
               help="The numbers of ram for the tenant use"),
    cfg.BoolOpt('test_all_provider_networks',
                default=False,
                help="Verify provider networks attached to guests"),
    cfg.StrOpt('overcloud_release',
               default=False,
               help="Overcloud release, for Red Hat OpenStack based clouds "
                    "use release numbers (10,13,16), for RDO based clouds "
                    "use release names ('Newton', 'Queens', 'Train').\n"
                    "This will expose different functionality during "
                    "invocation"),
]
