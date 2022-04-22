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

from enum import Enum
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from nfv_tempest_plugin.tests.scenario.multiqueue_manager \
    import MultiqueueClass
from oslo_log import log as logging
from tempest import config

import json
import os
import tempfile
import time

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class ABActionsEnum(Enum):
    OneCoreOverThreshold = 1
    OneCoreBelowThreshold = 2
    AllCoresOverThreshold = 3
    AllCoresBelowThreshold = 4


class TestMultiqueueScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestMultiqueueScenarios, self).__init__(*args, **kwargs)

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestMultiqueueScenarios, self).setUp()
        """ pre setup creations and checks read from config files """

    def test_mq_autob_deployment(self, test='mq_autob_deployment'):
        """Check that multiqueue/autobalance is properly configured

        Check that multiqueue and autobalance configuration parameters
        have been applied  properly during deployment.
        """
        LOG.info('Starting {} test.'.format(test))
        autob_dict = CONF.nfv_plugin_options.autobalance_config
        multiq_dict = CONF.nfv_plugin_options.multiqueue_config
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

    def test_mq_autob_over_threshold(self, test='mq_autob_over_threshold'):
        """Test autobalance takes place if over the threshold

            Check that autobalance takes place when one pmd is using more cpu
            than the configured while other pmd are not being used
        """
        LOG.info('Starting {} test.'.format(test))

        # Get trex and testpmd vms
        servers_dict = self.prepare_vms(test)

        # inject traffic and wait to see if rebalance takes place
        rebalance, cpu_under_threshold = self.\
            autobalance_functionality(servers_dict,
                                      ABActionsEnum.OneCoreOverThreshold)

        # evaluate if the testcase passed/failed
        msg = 'Failed to rebalance traffic, rebalance {}, ' \
              'cpu_under_threshold {}'.format(rebalance,
                                              cpu_under_threshold)
        self.assertTrue(rebalance and cpu_under_threshold, msg)

    def test_mq_autob_under_threshold(self, test='mq_autob_under_threshold'):
        """Test autobalance does not take place if under the threshold

            Check that autobalance does not takes place when cpu is under
            the threshold
        """
        LOG.info('Starting {} test.'.format(test))

        # Get trex and testpmd vms
        servers_dict = self.prepare_vms(test)

        # inject traffic and wait to see if rebalance takes place
        rebalance, cpu_under_threshold = self.\
            autobalance_functionality(servers_dict,
                                      ABActionsEnum.OneCoreBelowThreshold)

        # evaluate if the testcase passed/failed
        msg = 'Unexpected rebalance took place, rebalance {}, ' \
              'cpu_under_threshold {}'.format(rebalance,
                                              cpu_under_threshold)
        self.assertTrue(not rebalance and cpu_under_threshold, msg)

    def test_mq_autob_no_improvement(self, test='mq_autob_no_improvement'):
        """Test autobalance does not take place if no improvement

            Check that autobalance does not takes place when there is no
            improvement. In this case, all of the cpu cores will be loaded,
            so it will no make sense to rebalance
        """
        LOG.info('Starting {} test.'.format(test))

        # Get trex and testpmd vms
        servers_dict = self.prepare_vms(test)

        # inject traffic and wait to see if rebalance takes place
        rebalance, cpu_under_threshold = self.\
            autobalance_functionality(servers_dict,
                                      ABActionsEnum.AllCoresOverThreshold)

        # evaluate if the testcase passed/failed
        msg = 'Unexpected rebalance took place, rebalance {}, ' \
              'cpu_under_threshold {}'.format(rebalance,
                                              cpu_under_threshold)
        self.assertTrue(not rebalance and not cpu_under_threshold, msg)

    def test_mq_autob_interval(self, test='mq_autob_interval'):
        """Test autobalance interval

            Check that two reassignments should not take place in less
            than the interval configured
        """
        LOG.info('Starting {} test.'.format(test))

        # Get trex and testpmd vms
        servers_dict = self.prepare_vms(test)

        # inject traffic and wait to see if rebalance takes place
        rebalance, cpu_under_threshold = self.\
            autobalance_functionality(servers_dict,
                                      ABActionsEnum.OneCoreOverThreshold)

        msg = 'Failed to rebalance traffic, rebalance {}, ' \
              'cpu_under_threshold {}'.format(rebalance,
                                              cpu_under_threshold)
        self.assertTrue(rebalance and cpu_under_threshold, msg)

        start_time = time.time()
        # inject traffic and wait to see if rebalance takes place
        rebalance, cpu_under_threshold = self.\
            autobalance_functionality(servers_dict,
                                      ABActionsEnum.OneCoreOverThreshold)
        end_time = time.time()

        self.assertTrue(rebalance and cpu_under_threshold, msg)

        autob_dict = CONF.nfv_plugin_options.autobalance_config
        interval = int(autob_dict["pmd-auto-lb-rebal-interval"]) * 60

        LOG.info("Rebalance interval {}, threshold {}".
                 format(end_time - start_time, interval))

        msg2 = "Rebalance took place in less time ({}) than the configured " \
               "threshold ({}).".format(end_time - start_time, interval)
        self.assertTrue(end_time - start_time >= interval, msg2)

    def prepare_vms(self, test):
        """Check that vms needed to run testcases are present

            Testcases need 2 vms to be up and running: trex and testpmd
            trex and testpmd must be already running too

            param test: testcase name
            return servers_dict: trex and testpmd vms
        """
        # Resources should already be created
        if self.external_resources_data is None:
            raise ValueError('External resource data is required for the test')

        # Get servers metadata
        servers, key_pair = self.create_and_verify_resources(test=test)

        # Fail if there are no 2 servers
        if len(servers) != 2:
            raise ValueError('The test requires 2 servers configured')

        # Check which server is testpmd and trex
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

        # Fail if trex and testpmd were not identified
        if len(servers_dict) != 2:
            raise ValueError('Check that trex and testpmd are running')

        # Learn queues
        self.learn_queues(servers_dict["trex"], key_pair)

        return servers_dict

    def autobalance_functionality(self, servers_dict, action):
        """Inject traffic and check if rebalance takes place

            Testcases need 2 vms to be up and running: trex and testpmd
            trex and testpmd must be already running too

            param servers_dict: trex and testpmd vms
            param action: action to test (AutobalanceActionsEnum)
            return rebalance: Indicates if rebalance took place
            return cpu_under_threshold: Indicates if cpu is under threshold
                                        in all pmds
        """
        # Get multiqueue/autobalance parameters
        autob_dict = CONF.nfv_plugin_options.autobalance_config
        trex_queues_json_path = CONF.nfv_plugin_options.trex_queues_json_path
        load_threshold = float(autob_dict["pmd-auto-lb-load-threshold"])
        interval = int(autob_dict["pmd-auto-lb-rebal-interval"]) * 60

        # get multiqueue file from trex server
        queues_config = json.loads(servers_dict['trex']['ssh_source'].
                                   exec_command("cat {}".
                                                format(trex_queues_json_path)))

        # Create multiqueue management class
        multiqueue = MultiqueueClass(queues_config)

        # Get pmd/queues for the ports used to send/receive traffic
        ports_used = multiqueue.get_ports_used()
        pmd_cores = self. \
            get_pmd_cores_data(servers_dict["testpmd"]['hypervisor_ip'],
                               ports_used)

        if action == ABActionsEnum.OneCoreOverThreshold:
            # get rate to inject each queue to load over the threshold one pmd
            pps = multiqueue.load_one_core(pmd_cores,
                                           max(load_threshold * 1.2, 80))
        elif action == ABActionsEnum.OneCoreBelowThreshold:
            pps = multiqueue.load_one_core(pmd_cores,
                                           load_threshold * 0.5)
        elif action == ABActionsEnum.AllCoresOverThreshold:
            pps = multiqueue.load_all_cores(pmd_cores,
                                            max(load_threshold * 1.2, 80))
        elif action == ABActionsEnum.AllCoresBelowThreshold:
            pps = multiqueue.load_all_cores(pmd_cores,
                                            load_threshold * 0.5)

        # calculate the timeout for the injection
        # rebalance checked every pmd-auto-lb-rebal-interval minutes. We need
        # to check rebalance 2 times as in the first time it may be possible
        # that it is checked just when we have started traffic and the load
        # is not over the threshold yet.
        timeout = int(interval * 2.20)

        # create injection command and start injection
        inj_cmd = "/opt/trex/current/multiqueue.py  --action gen_traffic " \
                  "--traffic_json {} --pps \"{}\" --duration {} " \
                  "--multiplier {} > /tmp/multiqueue.log 2>&1 &". \
            format(trex_queues_json_path, pps, timeout, 1)

        LOG.info('Injection command {}'.format(inj_cmd))
        servers_dict['trex']['ssh_source'].exec_command(inj_cmd)

        # wait until rebalance takes place or timeout
        start_time = time.time()
        end_time = start_time
        rebalance = False
        cpu_under_threshold = False
        while (end_time - start_time) < timeout:
            pmd_cores_2 = self. \
                get_pmd_cores_data(servers_dict["testpmd"]['hypervisor_ip'],
                                   ports_used)
            rebalance = multiqueue. \
                check_rebalance(pmd_cores,
                                pmd_cores_2)
            if rebalance:
                break
            time.sleep(5)
            end_time = time.time()

        # Check if cpu cores are under the threshold
        # If rebalancing took place, it is needed some seconds to have
        # valid values. 10 seconds should be enough
        for iter in range(10):
            pmd_cores = self.get_pmd_cores_data(
                servers_dict["testpmd"]['hypervisor_ip'],
                ports_used)
            valid_values, cpu_under_threshold = multiqueue.\
                check_cpus_under_threshold(pmd_cores, load_threshold)
            if valid_values:
                break
            time.sleep(1)

        # stop injection if it is already running
        kill_cmd = "pkill -INT multiqueue.py || echo 0"
        LOG.info('Kill Injection command {}'.format(kill_cmd))
        servers_dict['trex']['ssh_source'].exec_command(kill_cmd)

        return rebalance, cpu_under_threshold

    def learn_queues(self, trex_vm, key_pair):
        """learn about queues

        Learn about queues:
        * mapping physical/virtual queues
        * rate/cpu params

        :param trex_vm: trex vm
        :param key_pair: key pair
        """
        injector_config = CONF.nfv_plugin_options.multiqueue_injector
        if not injector_config["learn"]:
            LOG.info('Skippeng multiqueue learning due to configuration.')
            return
        LOG.info('Starting multiqueue learning')

        # training cmd
        cmd_training = "{} --action gen_traffic --pps \"{}\" --traffic_json" \
                       " {} --duration {} --multiplier {}".\
            format(injector_config["path"],
                   injector_config["pps"],
                   injector_config["queues_json"],
                   injector_config["duration"],
                   injector_config["multiplier"])
        LOG.info('learn_queues cmd {}'.format(cmd_training))
        trex_vm['ssh_source'].exec_command(cmd_training)

        # get pmd stats
        cmd_pmd_rxq_show = "sudo ovs-appctl dpif-netdev/pmd-rxq-show"
        LOG.info('learn_queues cmd {}'.format(cmd_pmd_rxq_show))
        pmd_rxq_output = shell_utils.run_command_over_ssh(
            trex_vm['hypervisor_ip'],
            cmd_pmd_rxq_show)

        # copy pmd file to trex vm
        with tempfile.NamedTemporaryFile() as fp:
            fp.write(pmd_rxq_output.encode())
            fp.flush()
            self.copy_file_to_remote_host(trex_vm['fip'],
                                          key_pair['private_key'],
                                          self.instance_user,
                                          files=os.path.basename(fp.name),
                                          src_path=os.path.dirname(fp.name),
                                          dst_path=os.path.dirname(fp.name),
                                          timeout=60)

        # parse pmd file and update queues.json file
        cmd_pmd_parse = "{} --action parse_pmd_stats  --pmd_stats {} " \
                        "--traffic_json {} --pps \"{}\"".\
            format(injector_config["path"],
                   fp.name,
                   injector_config["queues_json"],
                   injector_config["pps"])
        LOG.info('learn_queues cmd {}'.format(cmd_pmd_parse))
        trex_vm['ssh_source'].exec_command(cmd_pmd_parse)

        LOG.info('Multiqueue learninng finished')
