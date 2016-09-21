from oslo_log import log
from tempest import config
from tempest.scenario import manager
from tempest import clients
import paramiko
import xml.etree.ElementTree as ET
from tempest.common.utils import data_utils
import StringIO


CONF = config.CONF
LOG = log.getLogger(__name__)

class BareMetalManager(manager.ScenarioTest):
    """This class Interacts with BareMetal settings
    """
    credentials = ['primary']

    @classmethod
    def setup_clients(cls):
        super(BareMetalManager, cls).setup_clients()
        cls.hypervisor_client = cls.manager.hypervisor_client
        cls.aggregates_client = cls.manager.aggregates_client

    def setUp(self):
        """check location of Private Key
        """
        super(BareMetalManager, self).setUp()
        self.assertIsNotNone(CONF.hypervisor.user, "Missing SSH user login in config")

        if CONF.hypervisor.private_key_file:
            key_str=open(CONF.hypervisor.private_key_file).read()
            CONF.hypervisor.private_key_file= paramiko.RSAKey.\
                from_private_key(StringIO.StringIO(key_str))
        else:
            self.assertIsNotNone(CONF.hypervisor.password, 'Missing SSH password and '
                                                       'key_file')
            self.password=CONF.hypervisor.password



    @classmethod
    def resource_setup(cls):
        super(BareMetalManager, cls).resource_setup()
        cls.tenant_id = cls.manager.identity_client.tenant_id


    @classmethod
    def setup_credentials(cls):
        super(BareMetalManager, cls).setup_credentials()

    @classmethod
    def _get_number_free_hugepages(self,host):
        """This Method Connects to Bare Metal and receive Number of free Memory Pages
        BareMetal on Bare Metal settings
        """
        command = "cat /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages"
        hugepages = self._run_command_over_ssh( host, command )
        return hugepages

    def create_flavor_with_extra_specs(self, name='flavor', vcpu=1, ram=2048, **extra_specs):
        flavor_with_hugepages_name = data_utils.rand_name(name)
        flavor_with_hugepages_id = data_utils.rand_int_id(start=1000)
        disk = 20
        self.flavors_client.create_flavor(
            name=flavor_with_hugepages_name, ram=ram, vcpus=vcpu, disk=disk,
            id=flavor_with_hugepages_id)
        self.flavors_client.set_flavor_extra_spec(flavor_with_hugepages_id, **extra_specs)
        self.addCleanup(self.flavors_client.delete_flavor, flavor_with_hugepages_id)
        return flavor_with_hugepages_id

    def _check_vcpu_with_xml(self, server,host):
        """This Method Connects to Bare Metal,Compute and return number of pinned CPUS
        """
        command = ("virsh -c qemu:///system dumpxml %s" % (server['OS-EXT-SRV-ATTR:instance_name']))
        cpuxml = self._run_command_over_ssh(self,host, command)
        string = ET.fromstring(cpuxml)
        s = string.findall('cputune')[0]
        for numofcpus in s.findall('vcpupin'):
            self.assertFalse(self.cpuregex.match(numofcpus.items()[1][1]) is None)

    def _check_numa_with_xml(self, server, host):
        """This Method Connects to Bare Metal,Compute and return number of Cells
        """
        command = ("virsh -c qemu:///system dumpxml %s" % (server['OS-EXT-SRV-ATTR:instance_name']))
        numaxml = self._run_command_over_ssh(self,host, command)
        string = ET.fromstring(numaxml)
        r = string.findall('cpu')[0]
        for i in r.findall('topology')[0].items():
            if i[0] == 'sockets':
                self.assertEqual(i[1], '1') ##change to 2
                print i[0]
        count = 0
        for i in r.findall('numa')[0].findall('cell'):
            if ((('id', '0')) in i.items() and (('memory', '2097152')) in i.items()):##change memory to 1572864
                count += 1
            if ((('id', '1')) in i.items() and (('memory', '2097152')) in i.items()): ##change cell id to 1 memory to 524288
                count += 1
        self.assertEqual(count, '2')

    @staticmethod
    def _run_command_over_ssh(host ,command):
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
        host=None

        if not name:
            return host

        aggregate = self.aggregates_client.list_aggregates()['aggregates']
#       Assertion check
        if aggregate:
            for i in aggregate:
                if name in i['name']:
                    aggregate.append(self.aggregates_client.show_aggregate(i['id'])[
                        'aggregate'])
            host=aggregate['hosts'][0]

        return host

    def _get_hypervisor_host_ip(self, name=None):
        """This Method lists aggregation based on name, and returns the aggregated
        search for IP through Hypervisor list API
        Add support in case of NoAggregation, and Hypervisor list is not empty
        if host=None, no aggregation, or name=None and if hypervisor list has one member
        return the member
        """
        host=None
        ip_address = ''
        if name:
            host = self._list_aggregate(name)

        hyper = self.manager.hypervisor_client.list_hypervisors()

        if host:
            for i in hyper['hypervisors']:
                if i['hypervisor_hostname'] == host:
                    ip_address=self.manager.hypervisor_client.show_hypervisor(i['id'])[
                        'hypervisor']['host_ip']
        else:
            for i in hyper['hypervisors']:
                if i['state'] == 'up':
                    ip_address=self.manager.hypervisor_client.show_hypervisor(i['id'])[
                        'hypervisor']['host_ip']

        return ip_address

    def _create_port(self, network_id, client=None, namestart='port-quotatest',
                 **kwargs):
        """This Method Overrides Manager::CreatePort to support direct and direct ph
        ports
        """
        kwargs['admin_state_up']='True'
        if not client:
            client = self.ports_client
        name = data_utils.rand_name(namestart)
        result = client.create_port(name=name,network_id=network_id,**kwargs)
        self.assertIsNotNone(result, 'Unable to allocate port')
        port=result['port']
        self.addCleanup(self.ports_client.delete_port, port['id'])
        return port

    def create_server(self, name=None, image_id=None, flavor=None,
                       validatable=False, wait_until=None,
                       wait_on_delete=True, clients=None, **kwargs):
        """This Method Overrides Manager::Createserver to support Gates needs
        """
        keypair = self.create_keypair()
        self.keypairs[keypair['name']] = keypair
        kwargs['key_name']=keypair['name']

        networks = self.networks_client.list_networks(
                       filters={'router:external': False})['networks']
        self.assertEqual(2, int(len(networks)),
                                 "There is more than one"
                                 " network for the tenant")
        net_id='None'
        for network in networks:
            if network['name'].lower().find('tempest') != -1:
                net_id = {'uuid': network['id']}


        server=super(BareMetalManager, self).create_server(name=name,
                                networks=[net_id],
                                key_name=keypair['name'],
                                image_id=image_id,
                                flavor=flavor,
                                wait_until='ACTIVE')
        self.servers.append(server)
        return server


