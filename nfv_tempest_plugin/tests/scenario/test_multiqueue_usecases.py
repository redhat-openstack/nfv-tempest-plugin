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
                queues = self.get_number_cqueues_for_interface(hypervisor_ip,
                                                               port['port'])
                if queues > 0:
                    ports_found.append({"port": port['port'],
                                        "queues": queues})

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

        hyperv_ok = [len(val) for val in result].count(0)
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
            if "testpmd" in out:
                servers_dict["testpmd"] = server
            elif "trex" in out:
                servers_dict["trex"] = server
            else:
                raise ValueError('Server {} does not have either trex or '
                                 'testpmd running'.format(server['fip']))

        # get multiqueue file from trex server
        queues_config = json.loads(servers['trex']['ssh_source'].exec_command(
            "cat {}".format(trex_queues_json_path)))

        MultiqueueClass multiqueue(queues_config)

        ports_used = multiqueue.get_ports_used()
        pmd_cores = self.\
            get_pmd_cores_data(servers["testpmd"]['hypervisor_ip'],
                               ports_used)
        pps = multiqueue.\
            load_one_core(pmd_cores,
                          autob_dict["pmd-auto-lb-load-threshold"])

        timeout = autob_dict["pmd-auto-lb-rebal-interval"] * 1.20
        injection_cmd = "/opt/trex/current/multiqueue.py -- traffic_json {} " \
                        "--pps \"{}\" --duration {} -- multiplier {} &".\
            format(trex_queues_json_path, pps, timeout, 1)

        queues_config = json.loads(servers['trex']['ssh_source'].exec_command(
            injection_cmd)

        start_time = time.time()
        end_time = start_time
        rebalance = False
        while (end_time - start_time) < timeout:
            pmd_cores_2 = self.\
                get_pmd_cores_data(servers["testpmd"]['hypervisor_ip'],
                                   ports_used)
            rebalance = multiqueue.\
                check_rebalance(pmd_cores,
                                pmd_cores_2,
                                autob_dict["pmd-auto-lb-load-threshold"])
            if rebalance:
                break
            time.sleep(5)
            end_time = time.time()

        self.assertTrue(rebalance, "Failed to rebalance traffic")

class MultiqueueClass:
    """" Manages multiqueue data """

    def __init__(self, queues_config):
        self.queues_config = queues_config
        self._calculate_cpu_func()
        self._create_queues_keys()

    def _calculate_cpu_func(self):
        self.pmd_cpu_a = (self.queues_config[0]['rate'] -
                          self.queues_config[1]['rate']) /\
                         (self.queues_config[0]['pmd_cpu'] -
                          self.queues_config[1]['pmd_cpu'])
        self.pmd_cpu_b = (self.queues_config[0]['pmd_cpu']) -\
                         (self.pmd_cpu_a * self.queues_config[0]['rate'])

    def _get_queues_key(self, name, id):
        return "{}_{}".format(name, id)

    def _create_queues_keys(self):
        self.queues_keys = {}
        for port in range(len(self.queues_config)):
            for hyp_port in self.queues_config[port]["hypervisor_ports"]:
                for queue in self.queues_config[port]["queues"].keys():
                    self.queues_keys[self._get_queues_key(hyp_port,queue)] =\
                        self.queues_config[port]["queues"]["queue"]

    def calculate_cpu(self, rate):
        return (self.pmd_cpu_a * rate + self.pmd_cpu_b)

    def calculate_rate(self, cpu):
        return (cpu - self.pmd_cpu_b) / dself.pmd_cpu_a

    def get_ports_used(self):
        ports_used = []
        [ports_used.extend(port['hypervisor_ports'])
         for port in self.queues_config]
        return ports_used

    def _clean_pmd_cores(self):
        for queue in self.queues_keys.values():
                queue["pmd_cores"] =[]

    def load_one_core(self, pmd_cores, minimum_load):
        self._clean_pmd_cores()
        chosen_core = None
        for core_id, queues in pmd_cores.items():
            for queue in queues["queues"].keys():
                self.queues_keys[queue]["pmd_cores"].append(core_id)
                # physical and virtual queues in the same pmd
                if len(set(self.queues_keys[key]["pmd_cores"])) <
                    len(self.queues_keys[key]["pmd_cores"]):
                    chosen_core = core_id
        # try if possible with a core in which same phys and virtual and
        # virtual queue are place, if not found, use any other core
        if not chosen_core:
            chosen_core = pmd_cores.keys()[0]

        load = max(minimum_load * 1.2, 90)
        load_per_queue = load / len(pmd_cores[chosen_core]["queues"])

        pps = [{}, {}]
        for port in range(len(self.queues_config)):
                for queue_id, queue_value in
                    self.queues_config[port]["queues"].items():
                    if chosen_core in queue_value["pmd_cores"]:
                        pps[port][queue_id] = load_per_queue

        return pps

    def multiqueue.check_rebalance(self, pmd_cores, pmd_cores_2, threshold)
        rebal = False
        cpu_under_threshold = True
        for core_id in pmd_cores.keys():
            if pmd_cores[core_id]["queues"].keys()  !=
                pmd_cores_2[core_id]["queues"].keys():
                rebal = True

        for queues in pmd_cores_2.values():
            cpu_val = 0
            for queue in queues["queues"].values():
                cpu_val += queue["pmd_usage"]
                if cpu_val > threshold:
                    cpu_under_threshold = False

        return rebal && cpu_under_threshold