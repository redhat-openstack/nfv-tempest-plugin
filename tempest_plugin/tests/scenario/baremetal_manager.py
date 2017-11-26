from oslo_log import log
from tempest import config
from tempest.scenario import manager
import paramiko
import xml.etree.ElementTree as ELEMENTTree
from tempest.lib.common.utils import data_utils
from tempest.lib.common.utils import test_utils
import textwrap
import base64
import re
from tempest.lib import exceptions as lib_exc

import StringIO
import yaml
import os.path
import subprocess as sp


CONF = config.CONF
LOG = log.getLogger(__name__)


class BareMetalManager(manager.ScenarioTest):
    """This class Interacts with BareMetal settings
    """
    credentials = ['primary', 'admin']

    def __init__(self, *args, **kwargs):
        super(BareMetalManager, self).__init__(*args, **kwargs)
        self.doc = None
        self.password = None
        self.external_config = None
        self.test_setup_dict = {}
        self.key_pairs = {}
        self.servers = []
        self.test_networks = {}
        self.test_network_dict = {}

    @classmethod
    def setup_clients(cls):
        super(BareMetalManager, cls).setup_clients()
        cls.hypervisor_client = cls.manager.hypervisor_client
        cls.aggregates_client = cls.manager.aggregates_client

    def setUp(self):
        """
        Check hypervisor configuration:
        SSH user and Private key/password definition [must].
        External config file exist [not a must].
        """
        super(BareMetalManager, self).setUp()
        self.assertIsNotNone(CONF.hypervisor.user,
                             "Missing SSH user login in config")

        if CONF.hypervisor.private_key_file:
            key_str = open(CONF.hypervisor.private_key_file).read()
            CONF.hypervisor.private_key = paramiko.RSAKey. \
                from_private_key(StringIO.StringIO(key_str))
        else:
            self.assertIsNotNone(CONF.hypervisor.password,
                                 'Missing SSH password or key_file')
        if CONF.hypervisor.external_config_file:
            if os.path.exists(CONF.hypervisor.external_config_file):
                self.read_external_config_file()

    @classmethod
    def resource_setup(cls):
        super(BareMetalManager, cls).resource_setup()
        cls.tenant_id = cls.manager.identity_client.tenant_id

    @classmethod
    def setup_credentials(cls):
        super(BareMetalManager, cls).setup_credentials()

    def _get_number_free_hugepages(self, host):
        """This Method Connects to Bare Metal and receive Number of free Memory Pages
        BareMetal on Bare Metal settings
        """
        command = "cat /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages"
        hugepages = self._run_command_over_ssh(host, command)
        return hugepages

    def read_external_config_file(self):
        """This Method reads network_config.yml
        reads data and assign it to dictionaries
        """
        with open(CONF.hypervisor.external_config_file, 'r') as f:
            self.external_config = yaml.load(f)

        """
        hold flavor list..
        hold net list.. translate to id
        """
        networks = self.networks_client.list_networks()['networks']
        flavors = self.flavors_client.list_flavors()['flavors']
        images = self.image_client.list_images()['images']

        """
        Iterate over networks mandatory vars in external_config are:
        port_type, gateway_ip
        """
        for net in self.external_config['networks']:
            self.test_network_dict[net['name']] = {'port_type': net['port_type'],
                                                   'gateway_ip': net['gateway_ip']}
            """
            Check for existence of optionals vars:
            router_name, external.
            """
            if 'external' in net:
                self.test_network_dict[net['name']]['external'] = net['external']
            if 'router_name' in net:
                self.test_network_dict[net['name']]['router'] = net['router_name']

        # iterate networks
        for net in self.test_network_dict.iterkeys():
            for network in networks:
                if network['name'] == net:
                    self.test_network_dict[net]['net-id'] = network['id']
        # Insert here every new parameter.
        for test in self.external_config['tests-setup']:
            if 'flavor' in test and test['flavor'] is not None:
                self.test_setup_dict[test['name']] = {'flavor': test['flavor']}
            if 'package-names' in test and test['package-names'] is not None:
                self.test_setup_dict[test['name']] = \
                    {'package-names': test['package-names']}
            if 'availability-zone' in test and test['availability-zone'] is not None:
                self.test_setup_dict[test['name']]['availability-zone'] = \
                    test['availability-zone']
            if 'image' in test and test['image'] is not None:
                self.test_setup_dict[test['name']]['image'] = \
                    test['image']
            if 'router' in test and test['router'] is not None:
                self.test_setup_dict[test['name']]['router'] = \
                    test['router']
            if 'service-names' in test and test['service-names'] is not None:
                self.test_setup_dict[test['name']]['service-names'] = \
                    test['service-names']
            if 'tuned-profile' in test and test['tuned-profile'] is not None:
                self.test_setup_dict[test['name']]['tuned-profile'] = \
                    test['tuned-profile']
            if 'mtu' in test and test['mtu'] is not None:
                self.test_setup_dict[test['name']]['mtu'] = \
                    test['mtu']

        # iterate flavors_id
        for test, test_param in self.test_setup_dict.iteritems():
            if 'flavor' in test_param:
                for flavor in flavors:
                    if test_param['flavor'] == flavor['name']:
                        self.test_setup_dict[test]['flavor-id'] = flavor['id']

        # iterate image_id
        for test, test_param in self.test_setup_dict.iteritems():
            if 'image' in test_param:
                for image in images:
                    if test_param['image'] == image['name']:
                        self.test_setup_dict[test]['image-id'] = image['id']

    def create_flavor_with_extra_specs(self, name='flavor', vcpu=1, ram=2048,
                                       **extra_specs):
        flavor_with_hugepages_name = data_utils.rand_name(name)
        flavor_with_hugepages_id = data_utils.rand_int_id(start=1000)
        disk = 20
        self.os_admin.flavors_client.create_flavor(
            name=flavor_with_hugepages_name, ram=ram, vcpus=vcpu, disk=disk,
            id=flavor_with_hugepages_id)
        self.os_admin.flavors_client.set_flavor_extra_spec(
            flavor_with_hugepages_id, **extra_specs)
        self.addCleanup(self.os_admin.flavors_client.delete_flavor,
                        flavor_with_hugepages_id)
        return flavor_with_hugepages_id

    def _check_vcpu_with_xml(self, server, host, cell_id='0'):
        """This Method Connects to Bare Metal,Compute and return number of pinned CPUS
        """
        instance_properties = \
            self.os_admin.servers_client.show_server(server['id'])['server']
        command = (
            "sudo virsh -c qemu:///system dumpxml %s" % (
                instance_properties['OS-EXT-SRV-ATTR:instance_name']))
        cpuxml = self._run_command_over_ssh(host, command)
        string = ELEMENTTree.fromstring(cpuxml)
        s = string.findall('cputune')[0]
        pinned_cpu_list = []
        for numofcpus in s.findall('vcpupin'):
            self.assertFalse(self.cpuregex.match(
                numofcpus.items()[1][1]) is None)
            pinned_cpu_list.append(numofcpus.items()[1][1])
        """
        check for existenace of CPU in NUMA cell
        array=( cpu1 cpu2 cpu3 ); for i in "${array[@]}";
        do if [ -d /sys/devices/system/cpu/cpu$i/node1 ] ;then echo $i; fi; done
        """
        format_list = " ".join(['{}'.format(x) for x in pinned_cpu_list])
        """
        In case of mix topology checking only node0 and verifying
        pinned_cpu_list > res.split()
        """
        mix_mode = 'mix' if cell_id == 'mix' else cell_id
        command = '''
        array=( {cpu_list} ); for i in "${{array[@]}}";do
        if [ -d /sys/devices/system/cpu/cpu$i/node{cell} ];then
        echo $i; fi; done'''.format(cell=cell_id, cpu_list=format_list)
        res = self._run_command_over_ssh(host, command)
        # !!! In case of Mix search for res smaller than pinned_cpu_list
        if mix_mode != 'mix':
            self.assertEqual(res.split(), pinned_cpu_list,
                             'number of vCPUs on cell '
                             '{cell} does not match to config {result}'.format(
                                 cell=cell_id, result=res.split))
        else:
            self.assertIsNot(len(res.split()), len(pinned_cpu_list),
                             'number of mix vCPUs on cell '
                             '{cell} is equal to config {result}'.format(
                                 cell=cell_id, result=res.split))

    def _check_numa_with_xml(self, server, host):
        """This Method Connects to Bare Metal,Compute and return number of Cells
           This method should be obsolete it is used by test_nfv_usecases
        """
        instance_properties = \
            self.os_admin.servers_client.show_server(server['id'])['server']
        command = (
            "virsh -c qemu:///system dumpxml %s" % (
                instance_properties['OS-EXT-SRV-ATTR:instance_name']))
        numaxml = self._run_command_over_ssh(host, command)
        string = ELEMENTTree.fromstring(numaxml)
        r = string.findall('cpu')[0]
        for i in r.findall('topology')[0].items():
            if i[0] == 'sockets':
                # change to 2
                self.assertEqual(i[1], '1')
                print i[0]
        count = 0
        for i in r.findall('numa')[0].findall('cell'):
            if (('id', '0') in i.items() and (
                    ('memory', '2097152')) in i.items()):  # change memory to 1572864
                count += 1
            if (('id', '1') in i.items() and (
                    ('memory',
                     '2097152')) in i.items()):  # change cell id to 1 memory to 524288
                count += 1
        self.assertEqual(count, '2')

    @staticmethod
    def _run_command_over_ssh(host, command):
        """This Method run Command Over SSH
        enter Host user, pass into configuration files
        """

        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        """Assuming all check done in Setup, otherwise Assert failing the test"""
        if CONF.hypervisor.private_key:
            ssh.connect(host, username=CONF.hypervisor.user,
                        pkey=CONF.hypervisor.private_key)
        else:
            ssh.connect(host, username=CONF.hypervisor.user,
                        password=CONF.hypervisor.password)

        stdin, stdout, stderr = ssh.exec_command(command)
        result = stdout.read()
        ssh.close()
        return result

    def _run_local_cmd_shell_with_venv(self, command, shell_file_to_exec=None):
        """This Method run command on tester local host
        shell_file_to_exec path to source file default is None
        TBD: Add support to return, hosts list
        TBD: Return None in case no aggregation found.
        """
        self.assertNotEmpty(command, "missing command parameter")
        if shell_file_to_exec is not None:
            source = 'source %s' % shell_file_to_exec
            pipe = sp.Popen(['/bin/bash', '-c', '%s && %s' % (source, command)],
                            stdout=sp.PIPE)
        else:
            pipe = sp.Popen(['/bin/bash', '-c', '%s' % command],
                            stdout=sp.PIPE)
        result = pipe.stdout.read()
        return result.split()

    def _list_aggregate(self, name=None):
        """This Method lists aggregation based on name, and returns the aggregated
        hosts lists
        TBD: Add support to return, hosts list
        TBD: Return None in case no aggregation found.
        """
        host = None

        if not name:
            return host

        aggregate = self.aggregates_client.list_aggregates()['aggregates']
        #       Assertion check
        if aggregate:
            aggr_result = []
            for i in aggregate:
                if name in i['name']:
                    aggr_result.append(self.aggregates_client.show_aggregate(i['id'])[
                        'aggregate'])
            host = aggr_result[0]['hosts']
        return host

    def _get_hypervisor_host_ip(self, name=None):
        """This Method lists aggregation based on name, and returns the aggregated
        search for IP through Hypervisor list API
        Add support in case of NoAggregation, and Hypervisor list is not empty
        if host=None, no aggregation, or name=None and if hypervisor list has one member
        return the member
        """
        host = None
        ip_address = ''
        if name:
            host = self._list_aggregate(name)

        hyper = self.manager.hypervisor_client.list_hypervisors()

        if host:
            for i in hyper['hypervisors']:
                if i['hypervisor_hostname'] == host:
                    ip_address = self.manager.hypervisor_client.show_hypervisor(i['id'])[
                        'hypervisor']['host_ip']
        else:
            for i in hyper['hypervisors']:
                if i['state'] == 'up':
                    ip_address = self.manager.hypervisor_client.show_hypervisor(i['id'])[
                        'hypervisor']['host_ip']
        return ip_address

    def _get_hypervisor_ip_from_undercloud(self, name=None, shell=None):
        """This Method lists aggregation based on name, and returns the aggregated
        search for IP through Hypervisor list API
        Add support in case of NoAggregation, and Hypervisor list is not empty
        if host=None, no aggregation, or name=None and if hypervisor list has one member
        return the member
        """
        host = None
        ip_address = ''
        if name:
            host = self._list_aggregate(name)

        hyper = self.manager.hypervisor_client.list_hypervisors()

        if host:
            host_name = re.split("\.", host[0])[0]
            if host_name is None:
                host_name = host

            for i in hyper['hypervisors']:
                if i['hypervisor_hostname'] == host[0]:
                    command = 'openstack ' \
                              'server show ' + host_name + \
                              ' -c \'addresses\' -f value | cut -d\"=\" -f2'
                    ip_address = self._run_local_cmd_shell_with_venv(command, shell)
        else:
            for i in hyper['hypervisors']:
                if i['state'] == 'up':
                    command = 'openstack server list -c \'Name\' -c \'Networks\' -f ' \
                              'value | grep -i compute | cut -d\"=\" -f2'
                    ip_address = self._run_local_cmd_shell_with_venv(command, shell)

        return ip_address

    def _create_test_networks(self):
        """
        Method read test-networks attributes from external_config.yml, to be created for
        tempest tenant, Do not use this method if the test need to run on pre-configured
        networks.. see _detect_existing_networks() method
        """
        if len(self.external_config['test-networks']) > 0:
            self.test_network_dict.clear()
        mgmt_network = None
        for net in self.external_config['test-networks']:
            self.test_network_dict[net['name']] = \
                {'provider:physical_network': net['physical_network'],
                 'provider:segmentation_id': net['segmentation_id'],
                 'provider:network_type': net['network_type'],
                 'dhcp': net['enable_dhcp'],
                 'cidr': net['cidr'],
                 'pool_start': net['allocation_pool_start'],
                 'pool_end': net['allocation_pool_end'],
                 'gateway_ip': net['gateway_ip'],
                 'port_type': net['port_type'],
                 'ip_version': net['ip_version']}
            if 'sec_groups' in net:
                self.test_network_dict[net['name']]['sec_groups'] = net['sec_groups']
            if 'mgmt' in net and net['mgmt']:
                mgmt_network = net['name']
        network_kwargs = {}
        """
        Create network and subnets
        """
        for net_name, net_param in self.test_network_dict.iteritems():
            network_kwargs.clear()
            network_kwargs['name'] = net_name
            if 'sec_groups' in net_param and net_param['sec_groups'] == False:
                network_kwargs['port_security_enabled'] = net_param['sec_groups']
            """Added this for VxLAN no need of physical network or segmentation
            """
            if 'provider:network_type' in net_param \
                    and net_param['provider:network_type'] == 'vlan':
                if 'provider:physical_network' in net_param:
                    network_kwargs['provider:physical_network'] =\
                        net_param['provider:physical_network']
                if 'provider:segmentation_id' in net_param:
                    network_kwargs['provider:segmentation_id'] =\
                        net_param['provider:segmentation_id']

            if 'provider:network_type' in net_param:
                network_kwargs['provider:network_type'] =\
                    net_param['provider:network_type']

            network_kwargs['tenant_id'] = self.networks_client.tenant_id
            result = self.os_admin.networks_client.create_network(**network_kwargs)
            network = result['network']
            self.assertEqual(network['name'], net_name)
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.os_admin.networks_client.delete_network,
                            network['id'])
            network_kwargs.clear()
            network_kwargs['network_id'] = network['id']
            self.test_network_dict[net_name]['net-id'] = network['id']
            network_kwargs['name'] = net_name + '_subnet'
            network_kwargs['ip_version'] = net_param['ip_version']
            if 'cidr' in net_param:
                network_kwargs['cidr'] = net_param['cidr']
            if 'gateway_ip' in net:
                network_kwargs['gateway_ip'] = net_param['gateway_ip']
            if 'dhcp' in net and not net_param['dhcp']:
                network_kwargs['dhcp'] = net_param['dhcp']
            if 'allocation_pool_start' in net_param:
                network_kwargs['allocation_pools'] = \
                    [{'start': net_param['allocation_pool_start'],
                      'end':net_param['allocation_pool_end']}]

            result = self.subnets_client.create_subnet(**network_kwargs)
            subnet = result['subnet']
            self.addCleanup(test_utils.call_and_ignore_notfound_exc,
                            self.subnets_client.delete_subnet, subnet['id'])
            self.test_network_dict[net_name]['subnet-id'] = subnet['id']
        if mgmt_network is not None:
            self.test_network_dict['public'] = mgmt_network

    def _add_subnet_to_router(self):
        """
        Method read test-networks attributes from external_config.yml, to be created for
        For VxLAN network type there is additional fork to be Done
        The following add to admin router mgmt subnet and create flowing ip
        """
        public_name = self.test_network_dict['public']
        public_net = self.test_network_dict[public_name]
        """
        search for admin router name

        """
        seen_routers = self.os_admin.routers_client.list_routers()['routers']
        self.assertEqual(len(seen_routers), 1,
                         "Test require 1 admin router. please check")
        self.os_admin.routers_client.add_router_interface(
             seen_routers[0]['id'], subnet_id=public_net['subnet-id'])
        self.addCleanup(self._try_remove_router_subnet,
                        seen_routers[0]['id'],
                        subnet_id=public_net['subnet-id'])

    def _try_remove_router_subnet(self, router, **kwargs):
        # delete router, if it exists
        try:
            self.os_admin.routers_client.remove_router_interface(
                router, **kwargs)
        # if router is not found, this means it was deleted in the test
        except lib_exc.NotFound:
                pass

    def _detect_existing_networks(self):
        """Use method only when test require no network cls.set_network_resources()
        it run over external_config networks, verified against existing networks..
        in case all networks exist return True and fill self.test_networks lists

        In case there is external router.. public network decided
        based on router_external=False and router is not None
        """
        self.assertIsNotNone(CONF.hypervisor.external_config_file,
                             'This test require missing extrnal_config, for this test')

        self.assertTrue(self.test_network_dict,
                        'No networks for test, please check external_config_file')

        public_network = self.networks_client.list_networks(
            **{'router:external': True})['networks']

        """
        Check public network exist in networks.
        remove it from network list
        if  = 0 we create port on first network if = 1  public network exist
        and set next network as vm management network
        name must not be public, router exist and network external false
        """
        if len(public_network) == 0:
            self.test_network_dict['public'] = self.test_network_dict.keys()[0]

        elif len(public_network) == 1:
            self.test_network_dict['public'] = None
            remove_network = None
            for net_name, net_param in self.test_network_dict.iteritems():
                if net_name != 'public' and 'router' in net_param \
                        and 'external' in net_param:
                    if not net_param['external']:
                        self.test_network_dict['public'] = net_name
                    else:
                        remove_network = net_name
            self.test_network_dict.pop(remove_network)

    def _create_ports_on_networks(self, **kwargs):
        """Use method only when test require no network cls.set_network_resources()
        it run over external_config networks, create networks as per test_network_dict
        In case there is external router public network decided
        This run over prepared network dictionary
        ports, unless port_security==False, ports created with rules
        """
        create_port_body = {'binding:vnic_type': '',
                            'namestart': 'port-smoke'}
        networks_list = []
        """
        set public network first
        """
        for net_name, net_param in self.test_network_dict.iteritems():
            if 'port_type' in net_param:
                create_port_body['binding:vnic_type'] = net_param['port_type']
                if 'security_groups' in kwargs and net_name == \
                        self.test_network_dict['public']:
                    create_port_body['security_groups'] = \
                        [s['id'] for s in kwargs['security_groups']]
                port = self._create_port(network_id=net_param['net-id'],
                                         **create_port_body)
                net_var = {'uuid': net_param['net-id'], 'port': port['id']}
                networks_list.append(net_var) \
                    if net_name != self.test_network_dict['public'] else \
                    networks_list.insert(0, net_var)
        if 'security_groups' in kwargs:
            [x.pop('id') for x in kwargs['security_groups']]
        return networks_list

    def _create_port(self, network_id, client=None, namestart='port-quotatest',
                     **kwargs):
        """This Method Overrides Manager::CreatePort to support direct and direct ph
        ports
        """
        kwargs['admin_state_up'] = 'True'
        if not client:
            client = self.ports_client
        name = data_utils.rand_name(namestart)
        result = client.create_port(name=name, network_id=network_id, **kwargs)
        self.assertIsNotNone(result, 'Unable to allocate port')
        port = result['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])
        return port

    def create_server(self, name=None, image_id=None, flavor=None,
                      validatable=False, wait_until=None,
                      wait_on_delete=True, clients=None, **kwargs):
        """This Method Overrides Manager::Createserver to support Gates needs
        :param validatable:
        :param clients:
        :param image_id:
        :param wait_on_delete:
        :param wait_until:
        :param flavor:
        :param name:
        """
        if 'key_name' not in kwargs:
            key_pair = self.create_keypair()
            self.key_pairs[key_pair['name']] = key_pair
            kwargs['key_name'] = key_pair['name']

        net_id = []
        networks = []
        if 'networks' in kwargs:
            net_id = kwargs['networks']
            kwargs.pop('networks', None)
        else:
            networks = self.networks_client.list_networks(
                **{'router:external': False})['networks']

        for network in networks:
            net_id.append({'uuid': network['id']})

        if 'availability_zone' in kwargs:
            if kwargs['availability_zone'] is None:
                kwargs.pop('availability_zone', None)

        server = super(BareMetalManager, self).create_server(name=name,
                                                             networks=net_id,
                                                             image_id=image_id,
                                                             flavor=flavor,
                                                             wait_until=wait_until,
                                                             **kwargs)
        self.servers.append(server)
        return server

    def _check_number_queues(self):
        """This method checks the number of max queues"""
        self.ip_address = \
            self._get_hypervisor_ip_from_undercloud(None, shell="/home/stack/stackrc")
        command = "tuna -t ovs-vswitchd -CP | grep pmd | wc -l"
        numpmds = int(self._run_command_over_ssh(self.ip_address[0], command))
        command = "sudo ovs-vsctl show | grep rxq | awk -F'rxq=' '{print $2}'"
        numqueues = self._run_command_over_ssh(self.ip_address[0], command)
        msg = "There are no queues available"
        self.assertNotEqual((numqueues.rstrip("\n")), '', msg)
        numqueues = int(filter(str.isdigit, numqueues.split("\n")[0]))
        maxqueues = numqueues * numpmds
        return maxqueues

    def _prepare_cloudinit_file(self):
        """This method create cloud-init file can be parsed duting nova boot
        It sets ssh user:passwd credentials, enable root login set default route
        and add additional interface and restart network"""
        gw_ip = self.test_network_dict[self.test_network_dict['public']]['gateway_ip']

        script = '''
                 #cloud-config
                 user: {user}
                 password: {passwd}
                 chpasswd: {{expire: False}}
                 ssh_pwauth: True
                 disable_root: 0
                 runcmd:
                 - cd /etc/sysconfig/network-scripts/
                 - cp ifcfg-eth0 ifcfg-eth1
                 - sed -i 's/'eth0'/'eth1'/' ifcfg-eth1
                 - echo {gateway}{gw_ip} >>  /etc/sysconfig/network
                 - systemctl restart network'''.format(gateway='GATEWAY=',
                                                       gw_ip=gw_ip,
                                                       user=self.ssh_user,
                                                       passwd=self.ssh_passwd)

        script_clean = textwrap.dedent(script).lstrip().encode('utf8')
        script_b64 = base64.b64encode(script_clean)
        return script_b64

    def _set_security_groups(self):
        """This method create security group except network marked with security
        groups == false in test_networks"""
        """
        Create security groups [icmp,ssh] for Deployed Guest Image
        """
        security_group = None
        mgmt_net = self.test_network_dict['public']
        if not ('sec_groups' in self.test_network_dict[mgmt_net] and
                self.test_network_dict[mgmt_net]['sec_groups'] == False):
            security_group = self._create_security_group()
            security_group = [{'name': security_group['name'],
                               'id': security_group['id']}]
        return security_group


