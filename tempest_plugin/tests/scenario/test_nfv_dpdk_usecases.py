from oslo_log import log as logging
from tempest import config
from tempest import clients
from tests.scenario import baremetal_manager
from tempest.common import credentials_factory as common_creds
from tempest import exceptions
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
        self.maxqueues = None

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
        self.maxqueues = super(TestDpdkScenarios, self)._check_number_queues()
        # pre setup creations and checks read from config files

    def _test_queue_functionality(self, queues):
        fip = dict()
        extra_specs = {'hw:mem_page_size': str("large")}
        if queues == "min":
            queues = self.maxqueues - 2
            wait_until = 'ACTIVE'
        elif queues == "odd":
            queues = self.maxqueues - 1
            wait_until = 'ACTIVE'
        elif queues == 'max':
            queues = self.maxqueues + 2
            wait_until = 'ERROR'
        else:
            queues = self.maxqueues
            wait_until = 'ACTIVE'
        flavor = self.create_flavor_with_extra_specs(vcpu=queues, **extra_specs)
        self._create_test_networks()
        super(TestDpdkScenarios, self)._create_ports_on_networks()
        try:
            instance = self.create_server(flavor=flavor, wait_until=wait_until)
        except exceptions.BuildErrorException:
            return False
        fip['ip'] = instance['addresses'][self.test_network_dict['public']][0]['addr']
        if 'router' in self.test_setup_dict['check-multiqueue-func']:
            if self.test_setup_dict['check-multiqueue-func']['router']:
                fip = self.create_floating_ip(self.instance, self.public_network)
        return self.ping_ip_address(fip['ip'])

    def test_min_queues_functionality(self):
        msg = "Could not create and ping instance with flavor contains " \
              "vcpus smaller than allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="min"), msg)

    def test_equal_queues_functionality(self):
        msg = "Could not create and ping instance with flavor contains " \
              "vcpus equal to allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="equal"), msg)

    def test_max_queues_functionality(self):
        msg = "Unexpectedly creating and ping to instance with flavor contains " \
              "vcpus greater than allowed amount of queues"
        self.assertFalse(self._test_queue_functionality(queues="max"), msg)

    def test_odd_queues_functionality(self):
        msg = "Could not create and ping instance with flavor contains " \
              "odd number of vcpus"
        self.assertTrue(self._test_queue_functionality(queues="odd"), msg)
