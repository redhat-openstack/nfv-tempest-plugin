# copyright 2017 red hat, inc.
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

from distutils.util import strtobool
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config

import json
import random
import re
import string
import tempfile
import time

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestMultiqueueScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestMultiqueueScenarios, self).__init__(*args, **kwargs)

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestMultiqueueScenarios, self).setUp()
        """ pre setup creations and checks read from config files """

    def test_multiqueu_deployment(self, test='multiqueue_deployment'):
        """Check that igmp snooping bonding is properly configure

        Check that multiqueue and autobalance configuration parameters
        have been applied  properly during deployment.
        """
        LOG.info('Starting {} test.'.format(test))
        autobalance_dict = json.loads(CONF.nfv_plugin_options.autobalance_config)
        multiqueue_dict = json.loads(CONF.nfv_plugin_options.multiqueue_config)

        hypervisors = self._get_hypervisor_ip_from_undercloud()

        result = []
        cmd_autob = 'sudo ovs-vsctl --format=json get open_vswitch . other_config'
        cmd_inter = ' ovs-vsctl  list Interface {} | grep -o -P "n_rxq.{0,4}" | awk -F '"' '{print $2}''

        checks = autobalance_dict
        checks['queues'] = multiqueue_dict

        for hypervisor_ip in hypervisors:
            ovs_data_filt = {}
            # parse cmd_autob command
            output_autob = shell_utils.run_command_over_ssh(hypervisor_ip, cmd_autob)
            ovs_data = json.loads(output_autob)
            try:
                for key in autobalance_dict.keys():
                    ovs_data_filt[key] = \
                    (ovs_data['data'][0]
                        [ovs_data['headings'].index(key)])
            except Exception:
                pass

            # parse cmd_inter command
            ports_found = []
            for port in multiqueue_dict:
                output_inter = shell_utils.run_command_over_ssh(hypervisor_ip, cmd_inter.format(port['port']))
                ports_found.append({"port":port['port'],"queues":output_inter})

            # check if all the parameters are properly configured
            diff_checks_cmd = (set(checks.keys())
                               - set(ovs_data_filt.keys()))
            if len(diff_checks_cmd) > 0:
                  result.append("{}. Missing checks: {}. Check ovs cmd "
                              "output".format(hypervisor_ip,
                                                ', '.join(diff_checks_cmd)))

            for check in checks:
                if check not in diff_checks_cmd:
                    if ovs_data_filt[check] != checks[check]:
                        msg = ("{}. Check failed: {}. Expected: {} "
                                "- Found: {}"
                                .format(hypervisor_ip, check, checks[check],
                                        ovs_data_filt[check]))
                        result.append(msg)
            self.assertTrue(len(result) == 0, '. '.join(result))

        return True
