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
    cfg.DictOpt('instance_repo',
                default={'epel': 'http://download.fedoraproject.org/pub/'
                         'epel/7/x86_64/'},
                help='A comma separated dictionaries of the repositories.'
                     'The format of the repo definition -'
                     'repo_name1: repo_url1, repo_name2: repo_url2'),
    cfg.ListOpt('install_packages',
                default=[],
                help='A list of packages to install'),
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
    cfg.StrOpt('quota_instances',
               default=100,
               help="The numbers of instances for the tenant use"),
    cfg.IntOpt('instance_def_gw_mtu',
               default=None,
               help="The default gateway mtu value for the instance to be "
                    "tested. The test pings the default gateway from the "
                    "default route interface. If not provided, tries to "
                    "discover the mtu size."),
    cfg.BoolOpt('test_all_provider_networks',
                default=False,
                help="Verify provider networks attached to guests"),
    cfg.StrOpt('login_security_group_rules',
               default='[{"protocol": "tcp", "direction": "ingress"'
                       ','
                       '"port_range_max": "22", "port_range_min": "22"}'
                       ','
                       '{"protocol": "icmp", "direction": "ingress"}]',
               help='Configuration for test security groups.'
                    'The format is JSON. '
                    '"protocol":<icmp/udp/tcp> - string '
                    '"direction":<ingress/egress> - string '
                    '"port_range_max":<max_port_range> - string '
                    '"port_range_min":<min_port_range> - string '),
    cfg.StrOpt('max_qos_rules',
               default='[{"max_kbps": 4000000, "max_burst_kbps": 4000000 }'
                       ','
                       ' {"max_kbps": 9000000, "max_burst_kbps": 4000000 }]',
               help='Configuration for max qos rules.'
                    'The format is JSON. '
                    '"max_kbps":<kbps> - string '
                    '"max_burst_kbps":<kbps> - string '),
    cfg.StrOpt('min_qos_rules',
               default='[{"min_kbps": 25000000}]',
               help='Configuration for min qos rules.'
                    'The format is JSON. '
                    '"min_kbps":<kbps> - string '),
    cfg.StrOpt('undercloud_rc_file',
               default='/home/stack/stackrc',
               help="Full path to undercloud rc file"
                    "usually called stackrc"),
    cfg.BoolOpt('use_neutron_api_v2',
                default=False,
                help="Use neutron-tempest-plugin clients"),
    cfg.IntOpt('hypervisor_wait_timeout',
               default=500,
               help='Timeout in seconds to wait for the '
                    'hypervisor reachability'),
    cfg.StrOpt('hypervisor_tuning_details',
               default='{"packages": ["tuned-2*", "tuned-profiles-*", '
                       '"openvswitch2*"], "services": ["tuned", '
                       '"openvswitch"], "tuned_profiles": ["cpu-partitioning",'
                       '"realtime-virtual-host"], "kernel_args": ["hugepages",'
                       '"hugepagesz", "default_hugepagesz", "iommu=pt",'
                       '"intel_iommu=on", "isolcpus", "nohz=on", "nohz_full",'
                       '"rcu_nocbs", "intel_pstate"]}',
               help='Hypervisor tuning details include: packages, '
                    'services, tuned profiles nad kernel arguments'),
    cfg.StrOpt('igmp_config',
               default='{"pkts_tolerance": 50, "mcast_groups":'
                       '[{"ip": "239.0.0.1", "port": "10000", "tx_pkts": 200,'
                       '"pkt_size": 20}, {"ip": "238.0.0.5", "port": "5000",'
                       '"tx_pkts": 300, "pkt_size": 20}]}',
               help='IGMP configuration for the igmp snooping test'),
    cfg.DictOpt('igmp_queries',
                default={'tcpdump_timeout': 200},
                help='IGMP configuration for the igmp queries test. '
                     'Configure tcpdump_timeout to set how long the test will '
                     'wait to receive igmp queries'),
    cfg.DictOpt('igmp_reports',
                default={'reports_interface': 'br-dpdk0'},
                help='IGMP configuration for the igmp reports test. '
                     'Configure reports_interface to set the interface in '
                     'which it will be checked that igmp reports are present'),
    cfg.ListOpt('offload_nics',
                default=[],
                help='Network interfaces to be tested for the offload test. '
                     'By default, the nics discovered automatically'),
    cfg.IntOpt('offload_num_vms',
               default=4,
               help="Num of vms in testcase test_offload_ovs_flows"),
    cfg.IntOpt('flows_timeout',
               default=10,
               help="Flows will expire if no packet is received during "
                    "this time"),
    cfg.IntOpt('offload_injection_time',
               default=10,
               help="Injection time for checking flows and traffic in "
                    "representor port in hwoffload testing"),
    cfg.StrOpt('kernel_args',
               default='default_hugepagesz=1GB hugepagesz=1G hugepages=64 '
                       'iommu=pt intel_iommu=on isolcpus=2-19,22-39',
               help='kernel args expected in the stack after update'),
    cfg.StrOpt('lacp_config',
               default='{"bond_mode": "balance-tcp", "lacp_time": "fast",'
                       '"lacp_status": "negotiated",'
                       '"lacp_fallback_ab": "true"}',
               help='LACP configuration for LACP deployment test.'),
    cfg.StrOpt('autobalance_config',
               default='{"pmd-auto-lb": "true",'
                       '"pmd-auto-lb-improvement-threshold": "25",'
                       '"pmd-auto-lb-load-threshold": "70",'
                       '"pmd-auto-lb-rebal-interval": "2",'
                       '"pmd-cpu-mask": "fc000fc"}',
               help='Autobalance configuration for testcase'),
    cfg.StrOpt('multiqueue_config',
               default='[{"port":"dpdk2", "queues":3},'
                       '{"port":"dpdk3", "queues":3}]',
               help='Multiqueue configuration for testcase'),
    cfg.StrOpt('trex_queues_json_path',
               default='/tmp/queues.json',
               help='Learned data from queues configuration'),
    cfg.DictOpt('multiqueue_learning',
                default={'injector': '/opt/trex/current/multiqueue.py',
                         'pps': [{'1': 0.3, '0': 1.2, '2': 0.1},
                                 {'1': 0.3, '0': 0.8, '2': 0.1}],
                         'queues_json': '/tmp/queues.json',
                         'duration': 40,
                         'multiplier': 1,
                         'learn': False,
                         'pmd_rxq_affinity': [
                             {'interface': 'dpdk2',
                              'pmd_rxq_affinity': '0:3,1:5,2:7'},
                             {'interface': 'dpdk3',
                              'pmd_rxq_affinity': '0:3,1:5,2:7'}
                         ]
                         },
                help='Multiqueue injector configuration')
]
