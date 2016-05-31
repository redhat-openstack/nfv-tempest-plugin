from oslo_log import log
from tempest.common.utils import data_utils
from tempest import clients
from tempest import config
from tests.scenario import baremetal_manager
from tempest.common import credentials_factory as common_creds
from tempest import test
import paramiko
import xml.etree.ElementTree as ET
import re


CONF = config.CONF
LOG = log.getLogger(__name__)

HUGEPAGE_SIZE = 1048576


class TestNfvScenarios(baremetal_manager.BareMetalManager):
    @classmethod
    def setup_credentials(cls):
        super(TestNfvScenarios, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_credentials(
                'identity_admin', fill_in=False))

    def setUp(self):
        super(TestNfvScenarios, self).setUp()
        self.cpuregex = re.compile('^[0-9]{1,2}$')
        self.hugepages_init = int(self._get_number_free_hugepages())

    def _get_number_free_hugepages(self):
        command = "cat /sys/kernel/mm/hugepages/hugepages-1048576kB/free_hugepages"
        hugepages = self._run_command_over_ssh('10.35.65.83', command)
        return hugepages[0]

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

    @test.attr(type='smoke')
    @test.idempotent_id('f323b3ba-82f8-4db7-8ea6-6a895869ec49')
    @test.services('compute', 'network')
    def test_hugepages(self):
        extra_specs = {'hw:mem_page_size': str(HUGEPAGE_SIZE)}
        flavor_id = self.create_flavor_with_extcra_specs(name="hugepages_flavor", **extra_specs)
        server1 = self.create_server(
            name=data_utils.rand_name('server'),
            flavor=flavor_id, wait_until='ACTIVE')
        count = self.flavors_client.show_flavor(
            self.servers_client.show_server(server1['id'])
            ['server']['flavor']['id'])['flavor']['ram'] / 1024
        server2 = self.create_server(name=data_utils.rand_name('server'),
                                     flavor=flavor_id,
                                     wait_until='ACTIVE')
        count += self.flavors_client.show_flavor(
            self.servers_client.show_server(
                server2['id'])['server']['flavor']['id'])['flavor']['ram'] / 1024
        actualresult = int(self._get_number_free_hugepages())
        self.assertEqual((self.hugepages_init - count), actualresult)

    def test_cpu_pinning(self):
        extra_specs = {'hw:mem_page_size': str(HUGEPAGE_SIZE), 'hw:cpu_policy': 'dedicated'}
        flavor_id_cpu = self.create_flavor_with_extra_specs(name="cpu_pinning_flavor", vcpu=2, **extra_specs)
        server = self.create_server(name=data_utils.rand_name('server'),
                                     flavor=flavor_id_cpu,
                                     wait_until='ACTIVE')
        self._check_vcpu_with_xml(server)
        print server

    def test_numa_sockets(self):
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh('10.35.65.83', command)
        self.assertTrue(int(result[0]) == 1) ##change to "> 1"
        extra_specs = {
            'hw:numa_nodes': '2', 'hw:numa_mempolicy': 'strict',
            'hw:numa_cpus.0': '0', 'hw:numa_cpus.1': '1',
            'hw:numa_mem.0': '1536', 'hw:numa_mem.1': '512'}
        extra_specs = {'hw:mem_page_size': str(HUGEPAGE_SIZE), 'hw:cpu_policy': 'dedicated'} ##delete after test finished
        flavor_id_numa = self.create_flavor_with_extra_specs(name="numa_flavor", vcpu=2, ram=2048, **extra_specs)
        server = self.create_server(name=data_utils.rand_name('server'),
                                    flavor=flavor_id_numa,
                                    wait_until='ACTIVE')
        self._check_numa_with_xml(server)
        print server

    def _check_vcpu_with_xml(self, server):
        command = ("virsh -c qemu:///system dumpxml %s" % (server['OS-EXT-SRV-ATTR:instance_name']))
        cpuxml = self._run_command_over_ssh('10.35.65.83', command)
        string = ET.fromstring(cpuxml)
        s = string.findall('cputune')[0]
        for numofcpus in s.findall('vcpupin'):
            self.assertFalse(self.cpuregex.match(numofcpus.items()[1][1]) is None)

    def _check_numa_with_xml(self, server):
        command = ("virsh -c qemu:///system dumpxml %s" % (server['OS-EXT-SRV-ATTR:instance_name']))
        numaxml = self._run_command_over_ssh('10.35.65.83', command)
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
    def _run_command_over_ssh(host, command, username='root', password='12345678'):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(host, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(command)
        result = stdout.read()
        return result

    def _get_hypervisor_host_ip(self):
        hyper = self.manager.hypervisor_client.list_hypervisors()
        for i in hyper['hypervisors']:
            print self.manager.hypervisor_client.show_hypervisor(i['id'])['hypervisor']['host_ip']