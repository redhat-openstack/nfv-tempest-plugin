from oslo_log import log as logging
from tempest import config
from tempest import clients
from tests.scenario import baremetal_manager
from tempest.common import credentials_factory as common_creds
from tempest import exceptions
import time
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
        try:
            self.maxqueues = super(TestDpdkScenarios, self)._check_number_queues()
        except:
            print("Hypervisor OVS not configured with MultiQueue")
        """ pre setup creations and checks read from config files """

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
            wait_until = 'ACTIVE'
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

    def _test_live_migration_block(self, test_instance_migration=None):
        """ Method boots an instance and wait until ACTIVE state.
        Migrates the instance to the next available hypervisor.
        """
        kwargs = {}
        count = 1
        import ipdb;ipdb.set_trace()
        if test_instance_migration:
            self.assertTrue(test_instance_migration in self.test_setup_dict,
                            "test requires {0}, setup in externs_config_file".
                            format(test_instance_migration))
            if 'flavor' in self.test_setup_dict[test_instance_migration]:
                self.flavor_ref = self.test_setup_dict[test_instance_migration]['flavor-id']
        else:
            extra_specs = {'hw:mem_page_size': str("large")}
            self.flavor_ref = self.create_flavor_with_extra_specs(vcpu=2, **extra_specs)
        self._create_test_networks()
        super(TestDpdkScenarios, self)._create_ports_on_networks()
        kwargs['user_data'] = super(TestDpdkScenarios, self)._prepare_cloudinit_file()
        try:
            instance = self.create_server(flavor=self.flavor_ref, wait_until='ACTIVE', **kwargs)
        except exceptions.BuildErrorException:
            return False
        host = self.os_admin.servers_client.show_server(instance['id'])['server']['OS-EXT-SRV-ATTR:hypervisor_hostname']
        self.os_admin.servers_client.live_migrate_server\
            (server_id=instance['id'], block_migration=True, disk_over_commit=True, host=None)
        """ Switch hypervisor id (compute-0 <=> compute-1) """
        if host[host.index('0')]:
            dest = list(host)
            dest[dest.index('0')] = '1'
            dest = ''.join(dest)
        else:
            dest = list(host)
            dest[dest.index('1')] = '0'
            dest = ''.join(dest)
        while (count < 30):
            count = +1
            time.sleep(3)
            if (self.os_admin.servers_client.show_server(instance['id'])
                ['server']['OS-EXT-SRV-ATTR:hypervisor_hostname'] == dest):
                return True
        return False

    def test_min_queues_functionality(self):
        msg = "Could not create and ping instance with flavor contains " \
              "vcpus smaller than allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="min"), msg)

    def test_equal_queues_functionality(self):
        msg = "Could not create and ping instance with flavor contains " \
              "vcpus equal to allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="equal"), msg)

    def test_max_queues_functionality(self):
        msg = "Could not create and ping instance with flavor contains " \
              "vcpus max to allowed amount of queues"
        self.assertTrue(self._test_queue_functionality(queues="max"), msg)

    def test_odd_queues_functionality(self):
        msg = "Could not create and ping instance with flavor contains " \
              "odd number of vcpus"
        self.assertTrue(self._test_queue_functionality(queues="odd"), msg)

    def test_live_migration_block(self):
        """ Make sure CONF.compute_feature_enabled.live_migration is True """
        msg = "Live migration Failed"
        self.assertTrue(self._test_live_migration_block(test_instance_migration="test_instance_migration"), msg)
