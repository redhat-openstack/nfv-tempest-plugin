from oslo_log import log
from tempest import clients
from tempest import config
from tempest.common import credentials_factory as common_creds
from tests.scenario import baremetal_manager
import re


CONF = config.CONF
LOG = log.getLogger(__name__)

HUGEPAGE_SIZE = 1048576


class TestDirectScenarios(baremetal_manager.BareMetalManager):

    @classmethod
    def setup_credentials(cls):
        super(TestDirectScenarios, cls).setup_credentials()
        cls.manager = clients.Manager(
             credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        self.image_ref = CONF.compute.image_ref  ## as explained earlier
        self.flavor_ref = CONF.compute.flavor_ref  ## as explained earlier
        self.keypairs = {}
        self.servers = []

        super(TestDirectScenarios, self).setUp()
        self.cpuregex = re.compile('^[0-9]{1,2}$')
        self.hypervisor_list=dict()
        self.ip_address = super(TestDirectScenarios,self)._get_hypervisor_host_ip('sriov')
        # The SSH login temporary disabled as we need to ensure to get the
        # proper hypervisor ip address.
        #self.hugepages_init = super(TestDirectScenarios,
        #                            self)._get_number_free_hugepages(self.ip_address)

    def test_direct_port(self):
        LOG.info("TestDirectNfvScenarios::test_server_sriov: started" )
        self.instance = super(TestDirectScenarios,self).create_server(image_id=self.image_ref,
                                          flavor=self.flavor_ref, wait_until='ACTIVE')
