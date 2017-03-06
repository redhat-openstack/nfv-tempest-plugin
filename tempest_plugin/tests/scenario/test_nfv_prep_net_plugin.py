from oslo_log import log as logging
from tempest import config
from tempest import clients
from tests.scenario import baremetal_manager
from tempest.common import credentials_factory as common_creds


LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestNfvPrepNetPlugin(baremetal_manager.BareMetalManager):
    def __init__(self, *args, **kwargs):
        super(TestNfvPrepNetPlugin, self).__init__(*args, **kwargs)
        self.image_ref = None
        self.flavor_ref = None
        self.ip_address = None
        self.public_network = None
        self.instance = None
        self.ssh_user = None
        self.availability_zone = None
        self.list_networks = None

    @classmethod
    def setup_credentials(cls):
        """
        Create no network resources for these tests, using public network for ssh
        """
        cls.set_network_resources()
        super(TestNfvPrepNetPlugin, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        """
        Set up a single tenant with an accessible server.
        If multi-host is enabled, save created server uuids.
        """
        super(TestNfvPrepNetPlugin, self).setUp()
        # pre setup creations and checks read from config files
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id
        self.ssh_user = CONF.validation.image_ssh_user
        self.list_networks = []

    def test_server_nfv_network_plugin(self):
        """
        The test shows how to deploy Guest with existing networks..
        external_config.. networks leaf need only network names and port types
        per test setup flavor-id, image-id, availability zone 
        The test identifies networks.. create ports preapre port list and parse it to vm

        consume test-setup
        """
        test_setup = 'numa0'
        """
        If the test demands external_config.. apply assertion check for config
        """
        self.assertTrue(test_setup in self.test_setup_dict,
                        "test requires {0}, setup in externs_config_file".
                        format(test_setup))
                            
        if 'flavor' in self.test_setup_dict[test_setup]:
            self.flavor_ref = self.test_setup_dict[test_setup]['flavor-id']
        
        if 'availability-zone' in self.test_setup_dict[test_setup]:
            self.availability_zone = self.test_setup_dict[test_setup]['availability-zone']

        """
        Create Keys for Deployed Guest Image
        """
        keypair = self.create_keypair()
        self.key_pairs[keypair['name']] = keypair
        """
        Create security groups [icmp,ssh] for Deployed Guest Image
        """
        kwargs = {}
        security_group = self._create_security_group()
        kwargs['security_groups'] = [{'name': security_group['name']}]

        super(TestNfvPrepNetPlugin, self)._detect_existing_networks() 
        kwargs['networks'] = super(TestNfvPrepNetPlugin, self).\
            _create_ports_on_networks(**kwargs)

        self.instance = self.create_server(key_name=keypair['name'],
                                           image_id=self.image_ref,
                                           flavor=self.flavor_ref,
                                           availability_zone=self.availability_zone,
                                           wait_until='ACTIVE', **kwargs)
        """
        Create floating ip to management port.
        """
        ip = None
        if self.test_network_dict['public'] in self.instance['addresses']:
            ip = self.instance['addresses'][self.test_network_dict['public']][0]['addr']

        """
        Run ping.
        """
        msg = "Timed out waiting for %s to become reachable" % ip
        self.assertTrue(self.ping_ip_address(ip), msg)
 

