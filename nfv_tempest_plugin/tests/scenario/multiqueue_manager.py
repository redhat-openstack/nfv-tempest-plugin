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

from oslo_log import log as logging
from tempest import config


CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class MultiqueueClass(object):
    """" Manages multiqueue data """

    def __init__(self, queues_config):
        self.queues_config = queues_config
        LOG.info('MultiqueueClass::__init__ queues_config '
                 '{}'.format(queues_config))
        self._calculate_cpu_func()
        self._create_queues_keys()

    def _calculate_cpu_func(self):
        """Parameterize rate/cpu

        rate = a * cpu + b
        With 2 points in the rect (cpu1, rate1), (cpu2, rate2),
        calculates a and b in order to be able to calculate
        rate to get a specific cpu load
        """
        self.pmd_cpu_a = (self.queues_config[0]['rate']
                          - self.queues_config[1]['rate']) /\
                         (self.queues_config[0]['pmd_cpu']
                          - self.queues_config[1]['pmd_cpu'])
        self.pmd_cpu_b = (self.queues_config[0]['rate']) -\
                         (self.pmd_cpu_a * self.queues_config[0]['pmd_cpu'])
        LOG.info('MultiqueueClass::_calculate_cpu_func a: {},'
                 ' b: {}'.format(self.pmd_cpu_a, self.pmd_cpu_b))

    def _get_queues_key(self, name, id):
        """Generate a key to identify queues

        :param name: port name
        :param id: queue id
        :return queue_key: queue key
        """
        return "{}_{}".format(name, id)

    def _create_queues_keys(self):
        """Create a structure to access queues through a key

        It will be able to access queues in self.queues_config
        in a easy way through the queue key
        """
        self.queues_keys = {}
        for port in range(len(self.queues_config)):
            for hyp_port in self.queues_config[port]["hypervisor_ports"]:
                for queue in self.queues_config[port]["queues"].keys():
                    self.queues_keys[self._get_queues_key(hyp_port, queue)] =\
                        self.queues_config[port]["queues"][queue]

    def calculate_cpu(self, rate):
        """Get cpu for a specific rate

        :param rate: rate to calculate
        :return cpu: cpu calculated for the rate
        """
        return (rate - self.pmd_cpu_b) / self.pmd_cpu_a

    def calculate_rate(self, cpu):
        """Get rate for a specific cpu value

        :param cpu: cpu to calculate
        :return rate: rate calculated for the cpu
        """
        return self.pmd_cpu_a * cpu + self.pmd_cpu_b

    def get_ports_used(self):
        """Get list of ports used by trex/testpmd

        Filter the port names to those ones of interest
        """
        ports_used = []
        [ports_used.extend(port['hypervisor_ports'])
         for port in self.queues_config]
        return ports_used

    def _clean_pmd_cores(self):
        """Clean pmd structure

        Clean pmd structure
        """
        for queue in self.queues_keys.values():
            queue["pmd_cores"] = []

    def load_one_core(self, pmd_cores, minimum_load):
        """Load one PMD core

        The goal is to have one PMD core load over the
        threshold. The other PMD cores could have some load,
        but before the threshold

        :param pmd_cores: list of pmd cores with its queues
        :param minimum_load: minimum load to get
        :return pps: list of pps to inject for each port and queue
        :            to get the goal of overload one pmd
        """
        self._clean_pmd_cores()
        chosen_core = None
        chosen_core_queues = 0
        for core_id, queues in pmd_cores.items():
            for queue in queues["queues"].keys():
                self.queues_keys[queue]["pmd_cores"].append(core_id)
            # chose a core with many queues
            if len(queues["queues"].keys()) > chosen_core_queues:
                chosen_core = core_id
                chosen_core_queues = len(queues["queues"].keys())
        LOG.info('MultiqueueClass::load_one_core chosen_core {}, '
                 'queues {}'.format(chosen_core, chosen_core_queues))
        LOG.info('MultiqueueClass::load_one_core chosen_core {}, '
                 'queues {}'.format(chosen_core, chosen_core_queues))

        load = max(minimum_load * 1.2, 80)
        load_per_queue = load / len(pmd_cores[chosen_core]["queues"])
        rate_per_queue = self.calculate_rate(load_per_queue)
        LOG.info('MultiqueueClass::load_one_core load {}'.format(load))
        LOG.info('MultiqueueClass::load_one_core load_per_queue {}'.
                 format(load_per_queue))
        LOG.info('MultiqueueClass::load_one_core rate_per_queue {}'.
                 format(rate_per_queue))

        pps = [{}, {}]
        for port in range(len(self.queues_config)):
            for queue_id, queue_value in \
                    self.queues_config[port]["queues"].items():
                if chosen_core in queue_value["pmd_cores"]:
                    pps[port][queue_id] = rate_per_queue

        return pps

    def check_rebalance(self, pmd_cores, pmd_cores_2):
        """Check if rebalance took place

        Rebalance takes places when queues are moved from one pmd
        to other one

        :param pmd_cores: initial pmd/queues configuration
        :param pmd_cores_2: final pmd/queues configuration
        :return rebal: Indicates if rebalance took place (True/False)
        """
        rebal = False
        LOG.info('MultiqueueClass::check_rebalance pmd_cores '
                 '{}'.format(pmd_cores_2))
        for core_id in pmd_cores.keys():
            if pmd_cores[core_id]["queues"].keys() != \
                    pmd_cores_2[core_id]["queues"].keys():
                rebal = True
                break

        LOG.info('MultiqueueClass::check_rebalance rebalance {}'.format(rebal))
        return rebal

    def check_cpus_under_threshold(self, pmd_cores, threshold):
        """Check if all pmds cpu usage is under the threshold

        After rebalance, it takes a while to have cpu values and pmd usage is
        set to -1, in that case, valid_cpu_values is set to False and
        cpu_under_threshold is invalid

        :param pmd_cores: pmd/queues configuration
        :param threshold: cpu threshold
        :return valid_cpu_values: Indicates if cpu values were present (True/False)
        :return cpu_under_threshold: Indicates if cpu values under threshold (True/False)
        """
        valid_cpu_values = True
        cpu_under_threshold = True
        LOG.info('MultiqueueClass::check_cpus_under_threshold pmd_cores '
                 '{}'.format(pmd_cores))
        for core_id in pmd_cores.keys():
            if not valid_cpu_values or not cpu_under_threshold:
                break
            cpu_val = 0
            for queue in pmd_cores[core_id]["queues"].values():
                if queue["pmd_usage"] < 0:
                    valid_cpu_values = False
                    break
                cpu_val += queue["pmd_usage"]
                if cpu_val > threshold:
                    cpu_under_threshold = False
                    LOG.info('MultiqueueClass::check_rebalance cpu over '
                             'threshold core_id: {}, cpu: {}, threshold: '
                             '{}'.format(core_id, cpu_val, threshold))
                    break
        return valid_cpu_values, cpu_under_threshold
