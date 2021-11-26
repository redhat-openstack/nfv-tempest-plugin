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
        self._calculate_cpu_func()
        self._create_queues_keys()

    def _calculate_cpu_func(self):
        self.pmd_cpu_a = (self.queues_config[0]['rate']
                          - self.queues_config[1]['rate']) /\
                         (self.queues_config[0]['pmd_cpu']
                          - self.queues_config[1]['pmd_cpu'])
        self.pmd_cpu_b = (self.queues_config[0]['pmd_cpu']) -\
                         (self.pmd_cpu_a * self.queues_config[0]['rate'])

    def _get_queues_key(self, name, id):
        return "{}_{}".format(name, id)

    def _create_queues_keys(self):
        self.queues_keys = {}
        for port in range(len(self.queues_config)):
            for hyp_port in self.queues_config[port]["hypervisor_ports"]:
                for queue in self.queues_config[port]["queues"].keys():
                    self.queues_keys[self._get_queues_key(hyp_port, queue)] =\
                        self.queues_config[port]["queues"]["queue"]

    def calculate_cpu(self, rate):
        return (self.pmd_cpu_a * rate + self.pmd_cpu_b)

    def calculate_rate(self, cpu):
        return (cpu - self.pmd_cpu_b) / self.pmd_cpu_a

    def get_ports_used(self):
        ports_used = []
        [ports_used.extend(port['hypervisor_ports'])
         for port in self.queues_config]
        return ports_used

    def _clean_pmd_cores(self):
        for queue in self.queues_keys.values():
            queue["pmd_cores"] = []

    def load_one_core(self, pmd_cores, minimum_load):
        self._clean_pmd_cores()
        chosen_core = None
        for core_id, queues in pmd_cores.items():
            for queue in queues["queues"].keys():
                self.queues_keys[queue]["pmd_cores"].append(core_id)
                # physical and virtual queues in the same pmd
                if len(set(self.queues_keys[queue]["pmd_cores"])) < \
                        len(self.queues_keys[queue]["pmd_cores"]):
                    chosen_core = core_id
        # try if possible with a core in which same phys and virtual and
        # virtual queue are place, if not found, use any other core
        if not chosen_core:
            chosen_core = pmd_cores.keys()[0]

        load = max(minimum_load * 1.2, 90)
        load_per_queue = load / len(pmd_cores[chosen_core]["queues"])

        pps = [{}, {}]
        for port in range(len(self.queues_config)):
            for queue_id, queue_value in \
                self.queues_config[port]["queues"].items():
                if chosen_core in queue_value["pmd_cores"]:
                    pps[port][queue_id] = load_per_queue

        return pps

    def check_rebalance(self, pmd_cores, pmd_cores_2, threshold):
        rebal = False
        cpu_under_threshold = True
        for core_id in pmd_cores.keys():
            if pmd_cores[core_id]["queues"].keys() != \
                pmd_cores_2[core_id]["queues"].keys():
                rebal = True

        for queues in pmd_cores_2.values():
            cpu_val = 0
            for queue in queues["queues"].values():
                cpu_val += queue["pmd_usage"]
                if cpu_val > threshold:
                    cpu_under_threshold = False

        ret = rebal & cpu_under_threshold
        return ret
