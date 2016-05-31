from oslo_log import log
from tempest import config
from tempest.scenario import manager

CONF = config.CONF
LOG = log.getLogger(__name__)

class BareMetalManager(manager.ScenarioTest):

    credentials = ['primary']
    @classmethod
    def setup_clients(cls):
        super(BareMetalManager, cls).setup_clients()
        # Hypervisor client
        cls.hypervisor_client = cls.manager.hypervisor_client

    def setUp(self):
        super(BareMetalManager, self).setUp()

    @classmethod
    def setup_credentials(cls):
        cls.set_network_resources()
        super(BareMetalManager, cls).setup_credentials()