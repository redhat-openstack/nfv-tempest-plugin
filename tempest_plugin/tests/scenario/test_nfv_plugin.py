from oslo_log import log as logging
from tempest import config
from tempest import clients
from tests.scenario import baremetal_manager
from tempest.common import credentials_factory as common_creds
from tempest.lib.common.utils import test_utils
from tempest.lib import exceptions as lib_exc

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestNfvPlugin(baremetal_manager.BareMetalManager):

    @classmethod
    def setup_credentials(cls):
        super(TestNfvPlugin, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        """Set up a single tenant with an accessible server.
        If multi-host is enabled, save created server uuids.
        """
        super(TestNfvPlugin, self).setUp()
        #pre setup creations and checks read from config files
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id
        self.ssh_user = CONF.validation.image_ssh_user
        self.key_pairs = {}
        self.servers = []


    def test_server_nfv_plugin(self):
        """
        Create Keys for Deployes Guest Image
        """
        keypair = self.create_keypair()
        # Create Keys for Deployed Guest Image
        self.keypairs[keypair['name']] = keypair
        # Create server with Genrated Keys
        self.instance = self.create_server(key_name=keypair['name'],
                                           image_id=self.image_ref,
                                           flavor=self.flavor_ref, wait_until='ACTIVE')
        # Create floating ip to management port.
        fip = self.create_floating_ip(self.instance, self.public_network)
        LOG.info("fip: %s, instance_id: %s", fip['ip'], self.instance["id"])
        # Run Ping test..
        msg = "Timed out waiting for %s to become reachable" % fip['ip']
        self.assertTrue(self.ping_ip_address( fip['ip']), msg)
        # Create ssh connection to fip with private keys..
        ssh_source = self.get_remote_client(
            fip['ip'], private_key=self.keypairs[self.instance['key_name']]['private_key'])
