from oslo_log import log
from tempest import config
from tempest.scenario import manager
import paramiko
import xml.etree.ElementTree as ET
from tempest.common.utils import data_utils
import StringIO
import yaml
import os.path

CONF = config.CONF
LOG = log.getLogger(__name__)


class BareMetalManager(manager.ScenarioTest):
    """This class Interacts with BareMetal settings
    """
    credentials = ['primary']

    def __init__(self, *args, **kwargs):
        super(BareMetalManager, self).__init__(*args, **kwargs)
        self.password = None
        self.external_config = None
        self.key_pairs = {}
        self.servers = []


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
        self.assertIsNotNone(CONF.hypervisor.user, "Missing SSH user login in config")

        if CONF.hypervisor.private_key_file:
            key_str = open(CONF.hypervisor.private_key_file).read()
            CONF.hypervisor.private_key_file = paramiko.RSAKey. \
                from_private_key(StringIO.StringIO(key_str))
        else:
            self.assertIsNotNone(CONF.hypervisor.password,
                                 'Missing SSH password or key_file')
        if CONF.hypervisor.external_config_file:
            if os.path.exists(CONF.hypervisor.external_config_file):
                with open(CONF.hypervisor.external_config_file, 'r') as f:
                    self.external_config = yaml.load(f)

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

    def create_flavor_with_extra_specs(self, name='flavor', vcpu=1, ram=2048,
                                       **extra_specs):
        flavor_with_hugepages_name = data_utils.rand_name(name)
        flavor_with_hugepages_id = data_utils.rand_int_id(start=1000)
        disk = 20
        self.flavors_client.create_flavor(
            name=flavor_with_hugepages_name, ram=ram, vcpus=vcpu, disk=disk,
            id=flavor_with_hugepages_id)
        self.flavors_client.set_flavor_extra_spec(flavor_with_hugepages_id, **extra_specs)
        self.addCleanup(self.flavors_client.delete_flavor, flavor_with_hugepages_id)
        return flavor_with_hugepages_id

    def _check_vcpu_with_xml(self, server, host):
        """This Method Connects to Bare Metal,Compute and return number of pinned CPUS
        """
        command = (
            "virsh -c qemu:///system dumpxml %s" % (
                server['OS-EXT-SRV-ATTR:instance_name']))
        cpuxml = self._run_command_over_ssh(host, command)
        string = ET.fromstring(cpuxml)
        s = string.findall('cputune')[0]
        for numofcpus in s.findall('vcpupin'):
            self.assertFalse(self.cpuregex.match(numofcpus.items()[1][1]) is None)

    def _check_numa_with_xml(self, server, host):
        """This Method Connects to Bare Metal,Compute and return number of Cells
        """
        command = (
            "virsh -c qemu:///system dumpxml %s" % (
                server['OS-EXT-SRV-ATTR:instance_name']))
        numaxml = self._run_command_over_ssh(host, command)
        string = ET.fromstring(numaxml)
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
        if CONF.hypervisor.private_key_file:
            ssh.connect(host, username=CONF.hypervisor.user,
                        pkey=CONF.hypervisor.private_key_file)
        else:
            ssh.connect(host, username=CONF.hypervisor.user,
                        password=CONF.hypervisor.password)

        stdin, stdout, stderr = ssh.exec_command(command)
        result = stdout.read()
        ssh.close()
        return result

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
            for i in aggregate:
                if name in i['name']:
                    aggregate.append(self.aggregates_client.show_aggregate(i['id'])[
                                         'aggregate'])
            host = aggregate['hosts'][0]

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

    def _detect_existing_networks(self):
        """Use method only when test require no network  cls.set_network_resources()
        it run over external_config networks, verified against existing networks..
        in case all networks exist return True and fill self.test_networks lists
        """
        self.assertIsNotNone(CONF.hypervisor.external_config_file,
                             'This test require missing extrnal_config, for this test')

        self.assertTrue(self.test_network_dict,
                        'No networks for test, please check external_config_file')

        public_network = self.networks_client.list_networks(
            **{'router:external': True})['networks']

        """
        Check public network exist in networks.
        """
        self.assertTrue(len(public_network) == 1,
                        msg="There 0 or more than 1 public network")
        self.test_network_dict['public'] = public_network[0]['name']


    def _create_ports_on_networks(self, **kwargs):
        """This run over prepared network dictionary
        ports, unless port_security==False, ports created with rules
        """
        create_port_body = {'binding:vnic_type': '',
                            'namestart': 'port-smoke'}
        networks_list = []
        """
        set public networ first
        """
        for net_name, net_param in self.test_network_dict.iteritems():
            if 'port_type' in net_param:
                create_port_body['binding:vnic_type'] = net_param['port_type']
                port = self._create_port(network_id=net_param['net-id'],
                                         **create_port_body)
                networks_list.append({'uuid': net_param['net-id'], 'port': port['id']})
                if net_name == self.test_network_dict['public']:
                    networks_list.insert(0, networks_list.pop())
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
        if 'key_name' not in dir(kwargs):
            key_pair = self.create_keypair()
            self.key_pairs[key_pair['name']] = key_pair
            kwargs['key_name'] = key_pair['name']

        if 'networks' not in dir(kwargs):
            networks = self.networks_client.list_networks(
                filters={'router:external': False})['networks']
        else:
            networks = kwargs['networks']

        net_id = None
        for network in networks:
            if network['router:external'] == False:
                net_id = [{'uuid': network['id']}]

        server = super(BareMetalManager, self).create_server(name=name,
                                                             networks=net_id,
                                                             image_id=image_id,
                                                             flavor=flavor,
                                                             wait_until=wait_until,
                                                             **kwargs)
        self.servers.append(server)
        return server
