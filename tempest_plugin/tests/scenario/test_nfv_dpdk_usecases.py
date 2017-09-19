from oslo_log import log as logging
from tempest import config
from tempest import clients
from tests.scenario import baremetal_manager
from tempest.common import credentials_factory as common_creds
from tempest import exceptions
from tempest.common import waiters
from tempest.lib.common.utils import data_utils
import base64
import textwrap
import re

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestDpdkScenarios(baremetal_manager.BareMetalManager):
    def __init__(self, *args, **kwargs):
        super(TestDpdkScenarios, self).__init__(*args, **kwargs)
        self.image_ref = None
        self.flavor_ref = None
        self.ip_address = None
        self.public_network = None
        self.instance = None
        self.ssh_user = None
        self.availability_zone = None
        self.list_networks = None
        self.cpuregex = re.compile('^[0-9]{1,2}$')
        self.image_ref = CONF.compute.image_ref
        self.flavor_ref = CONF.compute.flavor_ref
        self.public_network = CONF.network.public_network_id
        self.ssh_user = CONF.validation.image_ssh_user
        self.ssh_passwd = CONF.validation.image_ssh_password
        self.list_networks = []

    @classmethod
    def setup_credentials(cls):
        """
        Do not create network resources for these tests, using public network for ssh
        """
        cls.set_network_resources()
        super(TestDpdkScenarios, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        """
        Set up a single tenant with an accessible server.
        If multi-host is enabled, save created server uuids.
        """
        super(TestDpdkScenarios, self).setUp()
        # pre setup creations and checks read from config files

    def _test_queue_functionality(self, queues, wait_until=None):
        fip = dict()
        extra_specs = {'hw:mem_page_size': str("large")}
        flavor = self.create_flavor_with_extra_specs(vcpu=queues, **extra_specs)
        self._create_test_networks()
        super(TestDpdkScenarios, self)._create_ports_on_networks()
        try:
            instance = self.create_server(flavor=flavor, wait_until=wait_until)
        except exceptions.BuildErrorException:
            return False
        if self.test_setup_dict['check-multiqueue-func']['router']:
            fip = self.create_floating_ip(self.instance, self.public_network)
        else:
            fip['ip'] = instance['addresses'][self.test_network_dict['public']][0]['addr']
        return self.ping_ip_address(fip['ip'])

    def test_min_queues_functionality(self):
        self.assertTrue(self._test_queue_functionality(queues=self.maxqueues-2, wait_until='ACTIVE'))

    def test_equal_queues_functionality(self):
        self.assertTrue(self._test_queue_functionality(queues=self.maxqueues, wait_until='ACTIVE'))

    def test_max_queues_functionality(self):
        self.assertFalse(self._test_queue_functionality(queues=self.maxqueues+2, wait_until='ERROR'))

    def test_odd_queues_functionality(self):
        self.assertTrue(self._test_queue_functionality(queues=self.maxqueues-1, wait_until='ACTIVE'))
