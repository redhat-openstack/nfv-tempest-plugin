# Copyright 2019 Red Hat, Inc.
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
import math
import yaml

from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestDeriveParamsScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestDeriveParamsScenarios, self).__init__(*args, **kwargs)

    def setUp(self):
        """Set up a single tenant with an accessible server

        If multi-host is enabled, save created server uuids.
        """
        super(TestDeriveParamsScenarios, self).setUp()

    # Gets the numa nodes list
    def _get_numa_nodes(self, hypervisor_ip):
        nodes = []
        cmd = "sudo lscpu -p=NODE | grep -v ^#"
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        for line in output.split('\n'):
            if line:
                node = int(line.strip(' '))
                if node not in nodes:
                    nodes.append(node)
        return nodes

    def _get_nodes_cores_info(self, hypervisor_ip):
        dict_cpus = {}
        cmd = "sudo lscpu -p=NODE,CORE,CPU | grep -v ^#"
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        for line in output.split('\n'):
            if line:
                cpu_info = line.split(',')
                node = int(cpu_info[0])
                cpu = int(cpu_info[1])
                thread = int(cpu_info[2])
                # CPU and NUMA node together forms a unique value, as cpu is
                # specific to a NUMA node
                # NUMA node id and cpu id tuple is used for unique key
                dict_key = node, cpu
                if dict_key in dict_cpus:
                    if thread not in dict_cpus[dict_key]['thread_siblings']:
                        dict_cpus[dict_key]['thread_siblings'].append(thread)
                else:
                    cpu_item = {}
                    cpu_item['thread_siblings'] = [thread]
                    cpu_item['cpu'] = cpu
                    cpu_item['numa_node'] = node
                    dict_cpus[dict_key] = cpu_item
        return dict_cpus

    # Gets the DPDK NIC's mapping with NIC physical name and driver info
    # for the given MAC.
    def _get_dpdk_nics_mapping(self, hypervisor_ip, mac):
        cmd = "sudo cat /var/lib/os-net-config/dpdk_mapping.yaml"
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        dpdk_nics_map = yaml.safe_load(output)
        for dpdk_nic_map in dpdk_nics_map:
            if dpdk_nic_map['mac_address'] == mac:
                return dpdk_nic_map
        else:
            msg = ("Unable to determine DPDK NIC Mapping for "
                   "MAC: '%(mac)s'" % {'mac': mac})
            raise Exception(msg)

    # Gets the DPDK NIC's NUMA info
    def _get_dpdk_nics_info(self, hypervisor_ip):
        dpdk_nics_info = []
        dpdk_nics = []
        cmd = ("sudo ovs-vsctl --columns=name,type,admin_state "
               "--format=json list interface")
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        nics = json.loads(output)
        for nic in nics.get('data', []):
            if nic and str(nic[1]) == 'dpdk' and str(nic[2]) == 'up':
                dpdk_nics.append(str(nic[0]))
        if dpdk_nics:
            cmd = ("sudo ovs-vsctl --column=mac-in-use,mtu,status "
                   "--format=json list interface " + ' '.join(dpdk_nics))
            output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
            nics_info = json.loads(output)
            for nic_info in nics_info.get('data', []):
                data = {}
                data['mac'] = nic_info[0]
                data['mtu'] = nic_info[1]
                for field in nic_info[2][1]:
                    if field[0] == 'numa_id':
                        data['numa_node'] = int(field[1])
                        dpdk_nic_map = self._get_dpdk_nics_mapping(
                            hypervisor_ip, nic_info[0])
                        data['nic'] = dpdk_nic_map['name']
                        data['pci'] = dpdk_nic_map['pci_address']
                        dpdk_nics_info.append(data)
        return dpdk_nics_info

    # Gets the total physical memory.
    def _get_physical_memory(self, hypervisor_ip):
        mem_total_kb = 0
        cmd = "sudo dmidecode --type memory | grep 'Size' | grep '[0-9]'"
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        for line in output.split('\n'):
            if line:
                mem_info = line.split(':')[1].strip()
                mem_val = mem_info.split(' ')
                mem_unit = mem_val[1].strip(' ').lower()
                if mem_unit == 'kb':
                    memory_kb = int(mem_val[0].strip(' '))
                elif mem_unit == 'mb':
                    memory_kb = (int(mem_val[0].strip(' ')) * 1024)
                elif mem_unit == 'gb':
                    memory_kb = (int(mem_val[0].strip(' ')) * 1024 * 1024)
                mem_total_kb += memory_kb
        return (mem_total_kb / 1024)

    # Gets the DPDK PMD core list
    # Find the right logical CPUs to be allocated along with its
    # siblings for the PMD core list
    def _get_dpdk_core_list(self, hypervisor_ip, cpus, dpdk_nics_numa_info,
                            dpdk_nic_numa_cores_count=1):
        dpdk_core_list = []
        dpdk_nics_numa_nodes = [dpdk_nic['numa_node']
                                for dpdk_nic in dpdk_nics_numa_info]

        numa_cores = {}
        numa_nodes = self._get_numa_nodes(hypervisor_ip)
        for node in numa_nodes:
            if node in dpdk_nics_numa_nodes:
                numa_cores[node] = dpdk_nic_numa_cores_count
            else:
                numa_cores[node] = 1

        numa_nodes_threads = {}

        for cpu in cpus:
            if not cpu['numa_node'] in numa_nodes_threads:
                numa_nodes_threads[cpu['numa_node']] = []
            numa_nodes_threads[cpu['numa_node']].extend(cpu['thread_siblings'])

        for node, node_cores_count in numa_cores.items():
            numa_node_min = min(numa_nodes_threads[node])
            cores_count = node_cores_count
            for cpu in cpus:
                if cpu['numa_node'] == node:
                    # Adds threads from core which is not having least thread
                    if numa_node_min not in cpu['thread_siblings']:
                        dpdk_core_list.extend(cpu['thread_siblings'])
                        cores_count -= 1
                        if cores_count == 0:
                            break
        return ','.join([str(thread) for thread in sorted(dpdk_core_list)])

    # Gets host cpus
    def _get_host_cpus_list(self, hypervisor_ip, cpus):
        host_cpus_list = []

        numa_nodes_threads = {}
        # Creates a list for all available threads in each NUMA nodes
        for cpu in cpus:
            if not cpu['numa_node'] in numa_nodes_threads:
                numa_nodes_threads[cpu['numa_node']] = []
            numa_nodes_threads[cpu['numa_node']].extend(
                cpu['thread_siblings'])

        for numa_node in sorted(numa_nodes_threads.keys()):
            node = int(numa_node)
            # Gets least thread in NUMA node
            numa_node_min = min(numa_nodes_threads[numa_node])
            for cpu in cpus:
                if cpu['numa_node'] == node:
                    # Adds threads from core which is having least thread
                    if numa_node_min in cpu['thread_siblings']:
                        host_cpus_list.extend(cpu['thread_siblings'])
                        break

        return ','.join([str(thread) for thread in sorted(host_cpus_list)])

    # Computes round off MTU value in bytes
    # example: MTU value 9000 into 9216 bytes
    def _roundup_mtu_bytes(self, mtu):
        max_div_val = int(math.ceil(float(mtu) / float(1024)))
        return (max_div_val * 1024)

    # Calculates socket memory for a NUMA node
    def _calculate_node_socket_memory(self, numa_node, dpdk_nics_numa_info,
                                      overhead, packet_size_in_buffer,
                                      minimum_socket_memory):
        distinct_mtu_per_node = []
        socket_memory = 0

        # For DPDK numa node
        for nics_info in dpdk_nics_numa_info:
            if (numa_node == nics_info['numa_node']
                    and not nics_info['mtu'] in distinct_mtu_per_node):
                distinct_mtu_per_node.append(nics_info['mtu'])
                roundup_mtu = self._roundup_mtu_bytes(nics_info['mtu'])
                socket_memory += (((roundup_mtu + overhead)
                                   * packet_size_in_buffer) / (1024 * 1024))

        # For Non DPDK numa node
        if socket_memory == 0:
            socket_memory = minimum_socket_memory
        # For DPDK numa node
        else:
            socket_memory += 512

        socket_memory_in_gb = int(socket_memory / 1024)
        if socket_memory % 1024 > 0:
            socket_memory_in_gb += 1
        return (socket_memory_in_gb * 1024)

    # Gets the socket memory
    def _get_dpdk_socket_memory(self, hypervisor_ip, dpdk_nics_numa_info,
                                minimum_socket_memory=1500):
        dpdk_socket_memory_list = []
        overhead = 800
        packet_size_in_buffer = 4096 * 64
        numa_nodes = self._get_numa_nodes(hypervisor_ip)
        for node in numa_nodes:
            socket_mem = self._calculate_node_socket_memory(
                node, dpdk_nics_numa_info, overhead,
                packet_size_in_buffer,
                minimum_socket_memory)
            dpdk_socket_memory_list.append(socket_mem)
        return ','.join([str(sm) for sm in dpdk_socket_memory_list])

    # Gets nova cpus
    def _get_nova_cpus_list(self, hypervisor_ip, cpus, dpdk_cpus, host_cpus):
        nova_cpus_list = []
        threads = []
        # Creates a list for all available threads in each NUMA nodes
        for cpu in cpus:
            threads.extend(cpu['thread_siblings'])
        exclude_cpus_list = dpdk_cpus.split(',')
        exclude_cpus_list.extend(host_cpus.split(','))
        for thread in threads:
            if not str(thread) in exclude_cpus_list:
                nova_cpus_list.append(thread)
        return ','.join([str(thread) for thread in sorted(nova_cpus_list)])

    # Gets host isolated cpus
    def _get_host_isolated_cpus_list(self, dpdk_cpus, nova_cpus):
        host_isolated_cpus_list = [int(cpu) for cpu in dpdk_cpus.split(',')]
        host_isolated_cpus_list.extend(
            [int(cpu) for cpu in nova_cpus.split(',')])
        return (','.join([str(thread)
                for thread in sorted(host_isolated_cpus_list)]))

    # Gets the CPU model and flags
    def _get_cpu_details(self, hypervisor_ip):
        cmd = "sudo lscpu | grep 'Model name';sudo lscpu | grep 'Flags'"
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        if output:
            cpu_model = ""
            cpu_flags = []
            params = output.split('\n')
            if params:
                for param in params:
                    if "Model name" in param:
                        cpu_model = param.split(':')[1].strip(' \n')
                    elif "Flags" in param:
                        cpu_flags = param.split(':')[1].strip(' \n').split(' ')
            return cpu_model, cpu_flags
        else:
            msg = "Unable to determine 'CPU Model name'"
            raise Exception(msg)

    # Checks default 1GB hugepages support
    def _is_supported_default_hugepages(self, flags):
        return ('pdpe1gb' in flags)

    # Derives kernel_args parameter
    def _get_kernel_args(self, hypervisor_ip, hugepage_alloc_perc=50):
        kernel_args = {}
        cpu_model, cpu_flags = self._get_cpu_details(hypervisor_ip)
        if not self._is_supported_default_hugepages(cpu_flags):
            raise Exception("default huge page size 1GB is not supported")
        total_memory = self._get_physical_memory(hypervisor_ip)
        hugepages = int(float((total_memory / 1024) - 4)
                        * (hugepage_alloc_perc / float(100)))
        if cpu_model.startswith('Intel'):
            kernel_args['intel_iommu'] = 'on'
        kernel_args['iommu'] = 'pt'
        kernel_args['default_hugepagesz'] = '1GB'
        kernel_args['hugepagesz'] = '1G'
        kernel_args['hugepages'] = str(hugepages)
        return kernel_args

    # converts range list into number list
    # here input parameter and return value as list
    # example: ["12-14", "^13", "17"] into [12, 14, 17]
    def _convert_range_to_number_list(self, range_list):
        num_list = []
        exclude_num_list = []
        try:
            for val in range_list.split(','):
                val = val.strip(' ')
                if '^' in val:
                    exclude_num_list.append(int(val[1:]))
                elif '-' in val:
                    split_list = val.split("-")
                    range_min = int(split_list[0])
                    range_max = int(split_list[1])
                    num_list.extend(range(range_min, (range_max + 1)))
                else:
                    num_list.append(int(val))
        except ValueError as exc:
            err_msg = ("Invalid number in input param "
                       "'range_list': %s" % exc)
            raise Exception(err_msg)

        # here, num_list is a list of integers
        return (','.join([str(num)
                for num in num_list if num not in exclude_num_list]))

    def _get_node_nfv_status(self, hypervisor_ip):
        dpdk_status = False
        sriov_status = False
        cmd = ("sudo ovs-vswitchd --version | "
               "awk '{ if ($1 == \"DPDK\") print 1; }';"
               "echo '|';sudo cat /etc/puppet/hieradata/service_names.json")
        output = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
        if output:
            params = output.split('|')
            if params:
                if '1' in params[0].strip('\n'):
                    dpdk_status = True
                service_names = json.loads(params[1])
                if (service_names['service_names']
                        and "neutron_sriov_agent"
                        in service_names['service_names']):
                    sriov_status = True
        return dpdk_status, sriov_status

    # Derives the OvS DPDK and SRIOV parameters
    def _derive_parameters(self, hypervisor_ip,
                           dpdk_status, sriov_status):
        derived_params = {}
        dpdk_nics_info = self._get_dpdk_nics_info(hypervisor_ip)
        dict_cpus = self._get_nodes_cores_info(hypervisor_ip)
        cpus = list(dict_cpus.values())
        host_cpus_list = self._get_host_cpus_list(hypervisor_ip, cpus)
        dpdk_core_list = ""
        if dpdk_status:
            dpdk_core_list = self._get_dpdk_core_list(hypervisor_ip,
                                                      cpus, dpdk_nics_info)
            derived_params["OvsPmdCoreList"] = dpdk_core_list
            derived_params["OvsDpdkSocketMemory"] = \
                self._get_dpdk_socket_memory(hypervisor_ip, dpdk_nics_info)
            derived_params["OvsDpdkCoreList"] = host_cpus_list
        if dpdk_status or sriov_status:
            nova_cpus = self._get_nova_cpus_list(hypervisor_ip, cpus,
                                                 dpdk_core_list,
                                                 host_cpus_list)
            derived_params["NovaVcpuPinSet"] = nova_cpus
            derived_params["IsolCpusList"] = \
                self._get_host_isolated_cpus_list(dpdk_core_list, nova_cpus)
            derived_params["KernelArgs"] = \
                self._get_kernel_args(hypervisor_ip)
            # Recommended reserved host memory is 4096
            derived_params["NovaReservedHostMemory"] = '4096'
        return derived_params

    # Gets the OvS DPDK and SRIOV parameters current deployment values
    def _get_deployment_values(self, hypervisor_ip,
                               dpdk_status, sriov_status):
        host_params = {}
        retrive_host_params = {}
        if sriov_status:
            retrive_host_params = {
                'IsolCpusList': {'action': 'command',
                                 'cmd': (r"sudo cat /etc/tuned/bootcmdline | "
                                         r"grep -P -o 'nohz_full=.+?\s{1,}' |"
                                         r" sed 's/nohz_full=//'")},
                'KernelArgs': {'action': 'command',
                               'cmd': 'sudo cat /proc/cmdline'},
                'NovaReservedHostMemory': {'action': 'ini',
                                           'file_path': ('/var/lib/'
                                                         'config-data/'
                                                         'puppet-generated/'
                                                         'nova_libvirt/'
                                                         'etc/nova/'
                                                         'nova.conf'),
                                           'section': 'DEFAULT',
                                           'value': 'reserved_'
                                                    'host_memory_mb'},
                'NovaVcpuPinSet': {'action': 'ini',
                                   'file_path': ('/var/lib/config-data/'
                                                 'puppet-generated/'
                                                 'nova_libvirt/etc/nova/'
                                                 'nova.conf'),
                                   'section': 'DEFAULT',
                                   'value': 'vcpu_pin_set'}
            }
        if dpdk_status:
            retrive_host_params = {

                'IsolCpusList': {'action': 'command',
                                 'cmd': (r"sudo cat /etc/tuned/bootcmdline | "
                                         r"grep -P -o 'nohz_full=.+?\s{1,}' |"
                                         r" sed 's/nohz_full=//'")},
                'KernelArgs': {'action': 'command',
                               'cmd': 'sudo cat /proc/cmdline'},
                'NovaReservedHostMemory': {'action': 'ini',
                                           'file_path': ('/var/lib/'
                                                         'config-data/'
                                                         'puppet-generated/'
                                                         'nova_libvirt/etc/'
                                                         'nova/nova.conf'),
                                           'section': 'DEFAULT',
                                           'value': 'reserved_'
                                                    'host_memory_mb'},
                'NovaVcpuPinSet': {'action': 'ini',
                                   'file_path': ('/var/lib/config-data/'
                                                 'puppet-generated/'
                                                 'nova_libvirt/etc/nova/'
                                                 'nova.conf'),
                                   'section': 'DEFAULT',
                                   'value': 'vcpu_pin_set'},
                'OvsDpdkCoreList': {'action': 'command',
                                    'cmd': (r"sudo pgrep ovsdb-server | xargs "
                                            r"taskset -cp | grep -P -o '\d+' |"
                                            r" tail -n +2 | paste -s -d, -")},
                'OvsDpdkSocketMemory': {'action': 'command',
                                        'cmd': ("sudo ovs-vsctl get "
                                                "Open_vSwitch . other_config"
                                                ":dpdk-socket-mem")},
                'OvsPmdCoreList': {'action': 'command',
                                   'cmd': ("sudo ovs-appctl dpif-netdev/"
                                           "pmd-rxq-show | grep core_id | "
                                           "cut -d ' ' -f 6 | "
                                           "sed -e 's/://' | paste -s -d, -")},
            }
        for param in retrive_host_params:
            if retrive_host_params[param]['action'] == 'command':
                cmd = retrive_host_params[param]['cmd']
                result = shell_utils.run_command_over_ssh(hypervisor_ip, cmd)
            elif retrive_host_params[param]['action'] == 'ini':
                file_path = retrive_host_params[param]['file_path']
                section = retrive_host_params[param]['section']
                value = retrive_host_params[param]['value']
                result = shell_utils.\
                    get_value_from_ini_config(hypervisor_ip,
                                              file_path, section,
                                              value)
            host_params[param] = result.strip('\n').strip('"').strip()
            if (param in ['OvsDpdkCoreList', 'OvsPmdCoreList',
                          'NovaVcpuPinSet', 'IsolCpusList']):
                host_params[param] = \
                    self._convert_range_to_number_list(host_params[param])
            elif param == 'KernelArgs':
                kernel_args_str = host_params[param]
                kernel_args = kernel_args_str.split(' ')
                required_kernel_args = {}
                for arg in kernel_args:
                    kernel_param = arg.split('=')
                    if (('hugepages' in kernel_param[0])
                            or ('iommu' in kernel_param[0])):
                        required_kernel_args[str(kernel_param[0].strip())] = \
                            str(kernel_param[1].strip())
                host_params[param] = required_kernel_args
        return host_params

    def test_derived_parameters(self, test='derive_params'):
        """Test Derived Parameters

        This test compares the each parameters using derived values
        and current deployment values
        """
        derived_params = {}
        host_params = {}
        failures = []
        hypervisor_ip = self._get_hypervisor_ip_from_undercloud(
            shell='/home/stack/stackrc')[0]

        dpdk_status, sriov_status = self._get_node_nfv_status(hypervisor_ip)
        derived_params = self._derive_parameters(hypervisor_ip,
                                                 dpdk_status,
                                                 sriov_status)
        LOG.info("Derived parameters: {}".format(derived_params))
        host_params = self._get_deployment_values(hypervisor_ip,
                                                  dpdk_status,
                                                  sriov_status)
        LOG.info("Deployment parameters: {}".format(host_params))
        for param in host_params:
            if param not in derived_params:
                error = ("Derived parameter '{}' won't be parsed from "
                         "current deployment").format(param)
                failures.append(error)
                continue
            if host_params[param] != derived_params[param]:
                error = ("Derived parameter '{p}' {d_p} is not equal to "
                         "{h_p}").format(p=param,
                                         d_p=derived_params[param],
                                         h_p=host_params[param])
                failures.append(error)
        if failures:
            raise Exception(failures)
        else:
            return True
