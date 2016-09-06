from oslo_log import log
from tempest import clients
from tempest import config
from tempest.common.utils import data_utils
from tempest.common import credentials_factory as common_creds
from tempest import test
from tests.scenario import baremetal_manager
import re


CONF = config.CONF
LOG = log.getLogger(__name__)

HUGEPAGE_SIZE = 1048576


class TestNfvScenarios(baremetal_manager.BareMetalManager):

    @classmethod
    def setup_credentials(cls):
        super(TestNfvScenarios, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials(
                fill_in=False))

    def setUp(self):
        super(TestNfvScenarios, self).setUp()
        self.cpuregex = re.compile('^[0-9]{1,2}$')
        self.hugepages_init = int(self._get_number_free_hugepages())


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

