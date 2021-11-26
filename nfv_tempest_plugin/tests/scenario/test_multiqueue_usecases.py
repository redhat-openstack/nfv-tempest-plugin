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

from nfv_tempest_plugin.tests.scenario import base_test
from nfv_tempest_plugin.tests.scenario.multiqueue_manager \
    import MultiqueueClass
from oslo_log import log as logging
from tempest import config

import json
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

    def test_multiqueue_deployment(self, test='multiqueue_deployment'):
        """Check that igmp snooping bonding is properly configure

        Check that multiqueue and autobalance configuration parameters
        have been applied  properly during deployment.
        """
        LOG.info('Starting {} test.'.format(test))
        autob_dict = json.loads(CONF.nfv_plugin_options.autobalance_config)
        multiq_dict = json.loads(CONF.nfv_plugin_options.multiqueue_config)
        checks = autob_dict
        checks['queues'] = multiq_dict
        result = {}

        hypervisors = self._get_hypervisor_ip_from_undercloud()

        for hypervisor_ip in hypervisors:
            result[hypervisor_ip] = []
            ovs_data_filt = {}

            ovs_data = self.get_ovs_other_config_params(hypervisor_ip)
            for key in autob_dict.keys():
                if key in ovs_data:
                    ovs_data_filt[key] = ovs_data[key]

            ports_found = []
            for port in multiq_dict:
                queues = self.get_number_queues_for_interface(hypervisor_ip,
                                                               port['port'])
                if queues > 0:
                    ports_found.append({"port": port['port'],
                                        "queues": queues})
                ovs_data_filt['queues'] = ports_found

            # check if all the parameters are properly configured
            diff_checks_cmd = (set(checks.keys())
                               - set(ovs_data_filt.keys()))
            if len(diff_checks_cmd) > 0:
                result[hypervisor_ip].\
                    append("{}. Missing checks: {}. Check ovs cmd output".
                           format(hypervisor_ip, ', '.join(diff_checks_cmd)))

            for check in checks:
                if check not in diff_checks_cmd:
                    if ovs_data_filt[check] != checks[check]:
                        msg = ("{}. Check failed: {}. Expected: {} - "
                               "Found: {}"
                               .format(hypervisor_ip, check, checks[check],
                                       ovs_data_filt[check]))
                        result[hypervisor_ip].append(msg)

        hyperv_ok = [len(val) for val in result.values()].count(0)
        self.assertTrue(hyperv_ok > 0, str(result))

        return True

    def test_multiqueue_autobalance(self, test='multiqueue_autobalance'):
        """Test multiqueue autobalance

            Check that autobalance takes place when one pmd is using more cpu
            than the configured while other pmd are not being used
        """
        LOG.info('Starting {} test.'.format(test))

        if self.external_resources_data is None:
            raise ValueError('External resource data is required for the test')

        autob_dict = json.loads(CONF.nfv_plugin_options.autobalance_config)
        trex_queues_json_path = CONF.nfv_plugin_options.trex_queues_json_path

        servers, key_pair = self.create_and_verify_resources(test=test)

        if len(servers) != 2:
            raise ValueError('The test requires 2 servers configured')

        # check which server is testpmd and trex
        servers_dict = {}
        for server in servers:
            cmd = "ps -ef | egrep \"testpmd|trex\""
            server['ssh_source'] = self.get_remote_client(
                server['fip'],
                username=self.instance_user,
                private_key=key_pair['private_key'])
            out = server['ssh_source'].exec_command(cmd)
            if "dpdk-testpmd" in out:
                servers_dict["testpmd"] = server
            elif "t-rex-64" in out:
                servers_dict["trex"] = server
            else:
                raise ValueError('Server {} does not have either trex or '
                                 'testpmd running'.format(server['fip']))

        if len(servers_dict) != 2:
            raise ValueError('Check that trex and testpmd are running')

        # get multiqueue file from trex server
        queues_config = json.loads(servers_dict['trex']['ssh_source'].exec_command(
            "cat {}".format(trex_queues_json_path)))

        multiqueue = MultiqueueClass(queues_config)

        ports_used = multiqueue.get_ports_used()
        pmd_cores = self.\
            get_pmd_cores_data(servers_dict["testpmd"]['hypervisor_ip'],
                               ports_used)

        load_threshold = float(autob_dict["pmd-auto-lb-load-threshold"])
        pps = multiqueue.load_one_core(pmd_cores, load_threshold)

        # rebalance checked every pmd-auto-lb-rebal-interval minutes. We need to
        # check rebalance 2 times as in the first time it may be possible that
        # it is checked just when we have started traffic and the load is not
        # over the threshold yet.
        interval = int(autob_dict["pmd-auto-lb-rebal-interval"]) * 60
        timeout = int(interval * 2.20)
        injection_cmd = "/opt/trex/current/multiqueue.py  --action gen_traffic " \
                        "--traffic_json {} --pps \"{}\" --duration {} " \
                        "--multiplier {} > /tmp/multiqueue.log 2>&1 &".\
            format(trex_queues_json_path, pps, timeout, 1)

        LOG.info('Injection command {}'.format(injection_cmd))
        servers_dict['trex']['ssh_source'].exec_command(injection_cmd)

        start_time = time.time()
        end_time = start_time
        rebalance = False
        cpu_under_threshold = False
        while (end_time - start_time) < timeout:
            pmd_cores_2 = self.\
                get_pmd_cores_data(servers_dict["testpmd"]['hypervisor_ip'],
                                   ports_used)
            rebalance = multiqueue.\
                check_rebalance(pmd_cores,
                                pmd_cores_2)
            if rebalance:
                kill_cmd = "pkill -INT multiqueue.py || echo 0"
                LOG.info('Kill Injection command {}'.format(kill_cmd))
                servers_dict['trex']['ssh_source'].exec_command(kill_cmd)
                break
            time.sleep(5)
            end_time = time.time()

        if rebalance:
            # After rebalacing, pmd cpu usage takes some seconds to be available
            # data should be available in less than 10 seconds
            for iter in range(10):
                valid_values, cpu_under_threshold = multiqueue.\
                    check_cpus_under_threshold(pmd_cores_2, load_threshold)
                if valid_values:
                    break
                time.sleep(1)


        msg = 'Failed to rebalance traffic, rebalance {}, ' \
              'cpu_under_threshold {}'.format(rebalance,
                                              cpu_under_threshold)
        self.assertTrue(rebalance and cpu_under_threshold, msg)
