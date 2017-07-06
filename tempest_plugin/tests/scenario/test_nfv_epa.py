from oslo_log import log as logging
from tempest import config
from tempest import clients
from tests.scenario import baremetal_manager
from tempest.common import credentials_factory as common_creds
import base64
import textwrap
import re

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestBasicEpa(baremetal_manager.BareMetalManager):
    def __init__(self, *args, **kwargs):
        super(TestBasicEpa, self).__init__(*args, **kwargs)
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
        Create no network resources for these tests, using public network for ssh
        """
        cls.set_network_resources()
        super(TestBasicEpa, cls).setup_credentials()
        cls.manager = clients.Manager(
            credentials=common_creds.get_configured_admin_credentials())

    def setUp(self):
        """
        Set up a single tenant with an accessible server.
        If multi-host is enabled, save created server uuids.
        """
        super(TestBasicEpa, self).setUp()
        # pre setup creations and checks read from config files

    def test_numa0_provider_network(self):
        """
        The test shows how to deploy Guest with existing networks..
        external_config.. networks leaf need only network names and port types
        per test setup flavor-id, image-id, availability zone
        The test identifies networks.. create ports preapre port list and parse it to vm
        It relies on l3 provider network, no router
        consume test-setup

        numa_topology='numa0','numa1',numamix
        """

        """
        Check CPU mapping for numa0
        """
        self.ip_address = self._get_hypervisor_host_ip()
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh(self.ip_address, command)
        self.assertTrue(int(result[0]) == 2)

        test_setup_numa = "numa0"
        """
        If the test demands external_config.. apply assertion check for config
        """
        kwargs = {}
        self.assertTrue(test_setup_numa in self.test_setup_dict,
                        "test requires {0}, setup in externs_config_file".
                        format(test_setup_numa))

        if 'flavor' in self.test_setup_dict[test_setup_numa]:
            self.flavor_ref = self.test_setup_dict[test_setup_numa]['flavor-id']

        if 'availability-zone' in self.test_setup_dict[test_setup_numa]:
            kwargs['availability_zone'] = \
                self.test_setup_dict[test_setup_numa]['availability-zone']

        """
        Create Keys for Deployed Guest Image
        """
        keypair = self.create_keypair()
        self.key_pairs[keypair['name']] = keypair
        """
        Create security groups [icmp,ssh] for Deployed Guest Image
        """
        security_group = self._create_security_group()
        kwargs['security_groups'] = [{'name': security_group['name'],
                                      'id': security_group['id']}]

        super(TestBasicEpa, self)._detect_existing_networks()
        kwargs['networks'] = super(TestBasicEpa, self).\
            _create_ports_on_networks(**kwargs)

        gw_ip = self.test_network_dict[self.test_network_dict['public']]['gateway_ip']

        script = '''
                 #cloud-config
                 user: {user}
                 password: {passwd}
                 chpasswd: {{expire: False}}
                 ssh_pwauth: True
                 disable_root: 0
                 runcmd:
                 - cd /etc/sysconfig/network-scripts/
                 - cp ifcfg-eth0 ifcfg-eth1
                 - sed -i 's/'eth0'/'eth1'/' ifcfg-eth1
                 - echo {gateway}{gw_ip} >>  /etc/sysconfig/network
                 - systemctl restart network'''.format(gateway='GATEWAY=',
                                                       gw_ip=gw_ip,
                                                       user=self.ssh_user,
                                                       passwd=self.ssh_passwd)

        script_clean = textwrap.dedent(script).lstrip().encode('utf8')
        script_b64 = base64.b64encode(script_clean)
        kwargs['user_data'] = script_b64

        self.instance = self.create_server(key_name=keypair['name'],
                                           image_id=self.image_ref,
                                           flavor=self.flavor_ref,
                                           wait_until='ACTIVE', **kwargs)
        """
        Create floating ip to management port.
        """
        fip = self.create_floating_ip(self.instance, self.public_network)
        LOG.info("fip: %s, instance_id: %s", fip['ip'], self.instance["id"])
        """
        Run ping.
        """
        msg = "Timed out waiting for %s to become reachable" % fip['ip']
        self.assertTrue(self.ping_ip_address(fip['ip']), msg)
        self._check_vcpu_with_xml(self.instance, self.ip_address, test_setup_numa[4:])

    def test_numa1_provider_network(self):
        """
        The test shows how to deploy Guest with existing networks..
        external_config.. networks leaf need only network names and port types
        per test setup flavor-id, image-id, availability zone
        The test identifies networks.. create ports preapre port list and parse it to vm
        It relies on l3 provider network, no router
        consume test-setup

        numa_topology='numa0','numa1',numamix
        """

        """
        Check CPU mapping for numa1
        """
        self.ip_address = self._get_hypervisor_host_ip()
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh(self.ip_address, command)
        self.assertTrue(int(result[0]) == 2)

        test_setup_numa = "numa1"
        """
        If the test demands external_config.. apply assertion check for config
        """
        kwargs = {}
        self.assertTrue(test_setup_numa in self.test_setup_dict,
                        "test requires {0}, setup in externs_config_file".
                        format(test_setup_numa))

        if 'flavor' in self.test_setup_dict[test_setup_numa]:
            self.flavor_ref = self.test_setup_dict[test_setup_numa]['flavor-id']

        if 'availability-zone' in self.test_setup_dict[test_setup_numa]:
            kwargs['availability_zone'] = \
                self.test_setup_dict[test_setup_numa]['availability-zone']

        """
        Create Keys for Deployed Guest Image
        """
        keypair = self.create_keypair()
        self.key_pairs[keypair['name']] = keypair
        """
        Create security groups [icmp,ssh] for Deployed Guest Image
        """
        security_group = self._create_security_group()
        kwargs['security_groups'] = [{'name': security_group['name'],
                                      'id': security_group['id']}]

        super(TestBasicEpa, self)._detect_existing_networks()
        kwargs['networks'] = super(TestBasicEpa, self).\
            _create_ports_on_networks(**kwargs)

        gw_ip = self.test_network_dict[self.test_network_dict['public']]['gateway_ip']

        script = '''
                 #cloud-config
                 user: {user}
                 password: {passwd}
                 chpasswd: {{expire: False}}
                 ssh_pwauth: True
                 disable_root: 0
                 runcmd:
                 - cd /etc/sysconfig/network-scripts/
                 - cp ifcfg-eth0 ifcfg-eth1
                 - sed -i 's/'eth0'/'eth1'/' ifcfg-eth1
                 - echo {gateway}{gw_ip} >>  /etc/sysconfig/network
                 - systemctl restart network'''.format(gateway='GATEWAY=',
                                                       gw_ip=gw_ip,
                                                       user=self.ssh_user,
                                                       passwd=self.ssh_passwd)

        script_clean = textwrap.dedent(script).lstrip().encode('utf8')
        script_b64 = base64.b64encode(script_clean)
        kwargs['user_data'] = script_b64

        self.instance = self.create_server(key_name=keypair['name'],
                                           image_id=self.image_ref,
                                           flavor=self.flavor_ref,
                                           wait_until='ACTIVE', **kwargs)
        """
        Create floating ip to management port.
        """
        fip = self.create_floating_ip(self.instance, self.public_network)
        LOG.info("fip: %s, instance_id: %s", fip['ip'], self.instance["id"])
        """
        Run ping.
        """
        msg = "Timed out waiting for %s to become reachable" % fip['ip']
        self.assertTrue(self.ping_ip_address(fip['ip']), msg)
        self._check_vcpu_with_xml(self.instance, self.ip_address, test_setup_numa[4:])

