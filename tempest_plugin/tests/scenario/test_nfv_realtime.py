from oslo_log import log
from tempest import clients
from tempest import config
from tempest.common import credentials_factory as common_creds
from tempest import test
from tests.scenario import baremetal_manager
import re


CONF = config.CONF
LOG = log.getLogger(__name__)

HUGEPAGE_SIZE = 1048576


class TestRealTimeScenarios(baremetal_manager.BareMetalManager):
    """This class tests Real Time support
    """
    @classmethod
    def setup_credentials(cls):
        super(TestRealTimeScenarios, cls).setup_credentials()
        cls.manager = clients.Manager(
             credentials=common_creds.get_configured_admin_credentials(
                fill_in=False))

    def setUp(self):
        self.image_ref = CONF.compute.image_ref  ## as explained earlier
        self.flavor_ref = CONF.compute.flavor_ref  ## as explained earlier
        self.keypairs = {}
        self.servers = []

        super(TestRealTimeScenarios, self).setUp()
        self.cpuregex = re.compile('^[0-9]{1,2}$')
        self.hypervisor_list=dict()
        self.ip_address = super(TestRealTimeScenarios,self)._get_hypervisor_host_ip('realtime')
        self.hugepages_init = int(super(TestRealTimeScenarios,
                                    self)._get_number_free_hugepages(self.ip_address))
        self.assertNotEqual(self.hugepages_init, 0,
                                "there is no hugepage"
                                "on selected realtime node")

    def test_realtime_server(self):
        """This Method Creates real-time specified flavor and server
        """
        LOG.info("TestRealTimeNfvScenarios::test_realtime_server: started" )
        extra_specs = {'hw:memory_page_size': str(HUGEPAGE_SIZE), 
                       'hw:cpu_realtime': 'yes', 
                       'hw:cpu_realtime_mask': '^0',
                       'hw:cpu_policy': 'dedicated' }
        flavor_id_rt = self.create_flavor_with_extra_specs(name='rt_flavor', **extra_specs)
        self.instance = super(TestRealTimeScenarios,self).create_server(image_id=self.image_ref,
                                          flavor=flavor_id_rt, wait_until='ACTIVE')
