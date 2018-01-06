from oslo_log import log as logging
from tempest import config
from tempest import clients
from tempest_nfv_plugin.tests.scenario import baremetal_manager
from tempest.common import credentials_factory as common_creds
import re

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestBasicEpa(baremetal_manager.BareMetalManager):
    def __init__(self, *args, **kwargs):
        super(TestBasicEpa, self).__init__(*args, **kwargs)
        self.image_ref = None
        self.flavor_ref = None
        self.ip_address = None
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

    def _test_numa_provider_network(self, test_setup_numa):
        """
        The test shows how to deploy Guest with existing networks..
        external_config.. networks leaf need only network names and port types
        per test setup flavor-id, image-id, availability zone
        The test identifies networks.. create ports prepare port list and parse it to vm
        It relies on l3 provider network, no router
        consume test-setup

        numa_topology='numa0','numa1',numamix
        """

        """
        Check CPU mapping for numa0
        """
        """
           self.ip_address = self._get_hypervisor_host_ip()
           w/a to my_ip address set in nova fir non_contolled network, need access from
           tester """
        host_ip = self._get_hypervisor_ip_from_undercloud(None,
                                                          shell="/home/stack/stackrc")
        self.ip_address = host_ip[0]
        self.assertNotEmpty(self.ip_address, "_get_hypervisor_ip_from_undercloud"
                                             "returned empty ip list")
        command = "lscpu | grep 'NUMA node(s)' | awk {'print $3'}"
        result = self._run_command_over_ssh(self.ip_address, command)
        self.assertTrue(int(result[0]) == 2)

        """
        If the test demands external_config.. apply assertion check for config
        """
        kwargs = {}
        self.assertTrue(test_setup_numa in self.test_setup_dict,
                        "test requires {0}, setup in externs_config_file".
                        format(test_setup_numa))

        flavor_exists = super(TestBasicEpa,
                            self).check_flavor_existence(test_setup_numa)
        if flavor_exists is False:
            flavor_name = self.test_setup_dict[test_setup_numa]['flavor']
            self.flavor_ref = \
                super(TestBasicEpa,
                      self).create_flavor(**self.test_flavor_dict[flavor_name])

        if 'availability-zone' in self.test_setup_dict[test_setup_numa]:
            kwargs['availability_zone'] = \
                self.test_setup_dict[test_setup_numa]['availability-zone']

        router_exist = True
        if 'router' in self.test_setup_dict[test_setup_numa]:
            router_exist = self.test_setup_dict[test_setup_numa]['router']

        """
        Create Keys for Deployed Guest Image
        """
        keypair = self.create_keypair()
        self.key_pairs[keypair['name']] = keypair
        super(TestBasicEpa, self)._create_test_networks()
        security = super(TestBasicEpa, self)._set_security_groups()
        if security is not None:
            kwargs['security_groups'] = security
        kwargs['networks'] = super(TestBasicEpa,
                                   self)._create_ports_on_networks(**kwargs)
        kwargs['user_data'] = super(TestBasicEpa,
                                    self)._prepare_cloudinit_file()
        kwargs['key_name'] = keypair['name']

        self.instance = self.create_server(image_id=self.image_ref,
                                           flavor=self.flavor_ref,
                                           wait_until='ACTIVE', **kwargs)
        """
        Create floating ip to management port.
        """
        fip = dict()
        fip['ip'] = \
            self.instance['addresses'][self.test_network_dict['public']][0]['addr']
        if router_exist:
            super(TestBasicEpa, self)._add_subnet_to_router()
            fip = self.create_floating_ip(self.instance,
                                          self.public_network)

        LOG.info("fip: %s, instance_id: %s", fip['ip'], self.instance["id"])
        """
        Run ping and verify ssh connection.
        """
        msg = "Timed out waiting for %s to become reachable" % fip['ip']
        self.assertTrue(self.ping_ip_address(fip['ip']), msg)
        self.assertTrue(self.get_remote_client(fip['ip'],
                                           private_key=keypair['private_key']))
        self._check_vcpu_with_xml(self.instance, self.ip_address, test_setup_numa[4:])

    def test_numa0_provider_network(self):
        self._test_numa_provider_network("numa0")

    def test_numa1_provider_network(self):
        self._test_numa_provider_network("numa1")

    def test_numamix_provider_network(self):
        self._test_numa_provider_network("numamix")

    def _test_check_package_version(self, test_compute):
        """
        - Checks if package exists on hypervisors
        - If given - checks if the service is at active state
        - If given - checks the active tuned-profile

        * The test demands test_compute list
        """
        self.assertTrue(self.test_setup_dict[test_compute],
                        "test requires check-compute-packages "
                        "list in external_config_file")
        if 'availability-zone' in self.test_setup_dict[test_compute]:
            self.availability_zone = \
                self.test_setup_dict[test_compute]['availability-zone']
            host_ip = \
                self._get_hypervisor_ip_from_undercloud(self.availability_zone,
                                                        shell="/home/stack/stackrc")
            self.ip_address = host_ip[0]
        else:
            host_ip = self._get_hypervisor_ip_from_undercloud(None,
                                                              shell="/home/stack/stackrc")
            self.ip_address = host_ip[0]

        self.assertNotEmpty(self.ip_address, "_get_hypervisor_ip_from_undercloud"
                                             "returned empty ip list")
        if 'package-names' in self.test_setup_dict[test_compute]:
            if self.test_setup_dict[test_compute]['package-names'] is not None:
                command = "rpm -qa | grep %s" % \
                          self.test_setup_dict[test_compute]['package-names']
                result = self._run_command_over_ssh(self.ip_address, command)
                msg = "Packageg are {0} not found".format(
                    self.test_setup_dict[test_compute]['package-names'])
                self.assertTrue(
                    self.test_setup_dict[test_compute]['package-names'] in result, msg)
        if 'service-names' in self.test_setup_dict[test_compute]:
            if self.test_setup_dict[test_compute]['service-names'] is not None:
                command = "systemctl status %s | grep Active | awk '{print $2}'" % \
                          self.test_setup_dict[test_compute]['service-names']
                result = self._run_command_over_ssh(self.ip_address, command)
                msg = "services are {0} not Active".format(
                    self.test_setup_dict[test_compute]['service-names'])
                self.assertTrue('active' in result, msg)
        if 'tuned-profile' in self.test_setup_dict[test_compute]:
            if self.test_setup_dict[test_compute]['tuned-profile'] is not None:
                command = "sudo tuned-adm active | awk '{print $4}'"
                result = self._run_command_over_ssh(self.ip_address, command)
                msg = "Tuned {0} not Active".format(
                    self.test_setup_dict[test_compute]['tuned-profile'])
                self.assertTrue(
                    self.test_setup_dict[test_compute]['tuned-profile'] in result, msg)
        command = "sudo cat /proc/cmdline | grep nohz | grep nohz_full" \
                  " | grep rcu_nocbs | grep intel_pstate  | wc -l"
        result = self._run_command_over_ssh(self.ip_address, command)
        msg = "Tuned not set in grub need to reboot?"
        self.assertEqual(int(result), 1, msg)

    def test_packages_compute(self):
        self._test_check_package_version("check-compute-packages")

    def _test_mtu_ping_gateway(self, test_setup_mtu, mtu=1973):
        """
        The test boots an instance with given args from external_config_file,
        connect to the instance using ssh, and ping with given MTU to GW.
        * This tests depend on MTU configured at running environment.
        """
        kwargs = {}
        router_exist = None
        if 'availability-zone' in self.test_setup_dict[test_setup_mtu]:
            self.availability_zone = \
                self.test_setup_dict[test_setup_mtu]['availability-zone']

        flavor_exists = super(TestBasicEpa,
                              self).check_flavor_existence(test_setup_mtu)
        if flavor_exists is False:
            flavor_name = self.test_setup_dict[test_setup_mtu]['flavor']
            self.flavor_ref = \
                super(TestBasicEpa,
                      self).create_flavor(**self.test_flavor_dict[flavor_name])

        if 'router' in self.test_setup_dict[test_setup_mtu]:
            router_exist = self.test_setup_dict[test_setup_mtu]['router']
        if 'mtu' in self.test_setup_dict[test_setup_mtu]:
            mtu = self.test_setup_dict[test_setup_mtu]['mtu']
        keypair = self.create_keypair()
        self.key_pairs[keypair['name']] = keypair
        super(TestBasicEpa, self)._create_test_networks()
        security = super(TestBasicEpa, self)._set_security_groups()
        if security is not None:
            kwargs['security_groups'] = security
        kwargs['networks'] = super(TestBasicEpa,
                                   self)._create_ports_on_networks(**kwargs)
        kwargs['user_data'] = super(TestBasicEpa,
                                    self)._prepare_cloudinit_file()
        self.instance = self.create_server(key_name=keypair['name'],
                                           image_id=self.image_ref,
                                           flavor=self.flavor_ref,
                                           wait_until='ACTIVE', **kwargs)
        fip = dict()
        fip['ip'] = \
            self.instance['addresses'][self.test_network_dict['public']][0]['addr']
        if router_exist is not None and router_exist:
            super(TestBasicEpa, self)._add_subnet_to_router()
            fip = self.create_floating_ip(self.instance,
                                          self.public_network)
        msg = "Timed out waiting for %s to become reachable" % fip['ip']
        self.assertTrue(self.ping_ip_address(fip['ip']), msg)
        gateway = self.test_network_dict[self.test_network_dict['public']]['gateway_ip']
        gw_msg = "The gateway of given network does not exists,".\
            join("please assign it and re-run.")
        self.assertTrue(gateway is not None, gw_msg)
        ssh_source = self.get_remote_client(fip['ip'],
                                            private_key=self.key_pairs
                                            [self.instance['key_name']]['private_key'])
        return ssh_source.exec_command('ping -c 1 -M do -s %d %s' % (mtu, gateway))

    def test_mtu_ping_test(self):
        msg = "MTU Ping test failed - check your environment settings"
        self.assertTrue(self._test_mtu_ping_gateway("test-ping-mtu"), msg)
