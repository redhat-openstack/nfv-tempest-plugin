# Copyright 2017 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import fnmatch
import json
import time

from nfv_tempest_plugin.services.redfish_client import RedfishClient
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest.common import waiters
from tempest import config


CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestNfvBasic(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestNfvBasic, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(TestNfvBasic, self).setUp()
        # pre setup creations and checks read from config files

    def test_hypervisor_tuning(self, test='hypervisor_tuning'):
        """Test tuning state of hypervisor

        Test the following states:
          - Packages (given in config)
          - Active services (given in config)
          - Tuned active profile (given in config)
          - Kernel arguments (given in config)
        """
        tuning_details = \
            json.loads(CONF.nfv_plugin_options.hypervisor_tuning_details)
        packages = tuning_details.get("packages")
        services = tuning_details.get("services")
        tuned_profiles = tuning_details.get("tuned_profiles")
        kernel_args = tuning_details.get("kernel_args")

        if CONF.nfv_plugin_options.target_hypervisor:
            self.hypervisor_ip = \
                self._get_hypervisor_ip_from_undercloud(
                    hyper_name=CONF.nfv_plugin_options.target_hypervisor)
        self.hypervisor_ip = self._get_hypervisor_ip_from_undercloud()[0]
        self.assertNotEmpty(self.hypervisor_ip, "No hypervisor found")

        test_result = []
        if packages:
            pkg_check = "rpm -qa | grep"
            for package in packages:
                tmpl = " -e ^{}"
                pkg_check += tmpl.format(package)
            result = shell_utils.run_command_over_ssh(self.hypervisor_ip,
                                                      pkg_check).split()
            if result:
                for pkg in packages:
                    if not fnmatch.filter(result, pkg):
                        test_result.append("Missing required packages. "
                                           "Found following packages: {}"
                                           .format(result))
                LOG.info("Found the following packages: {}".format(result))
            else:
                test_result.append("Packages: no output received")

        if services:
            svc_check = "systemctl is-active"
            for service in services:
                svc_check += " {}".format(service)
            result = shell_utils.run_command_over_ssh(self.hypervisor_ip,
                                                      svc_check).strip('\n')
            if result:
                if result.split('\n').count('active') != len(services):
                    test_result.append("Some of the requested services are "
                                       "not in an active state.")
                LOG.info('The services states - {}'
                         .format(list(zip(services, result.split('\n')))))
            else:
                test_result.append("Services: no output received")

        if tuned_profiles:
            cmd = "sudo tuned-adm active | awk '{print $4}'"
            result = shell_utils.run_command_over_ssh(self.hypervisor_ip,
                                                      cmd).strip('\n')
            if result not in tuned_profiles:
                test_result.append("Tuned {0} profile is not Active"
                                   .format(tuned_profiles))

        if kernel_args:
            grub_output_cmd = "sudo cat /proc/cmdline"
            result = shell_utils.run_command_over_ssh(self.hypervisor_ip,
                                                      grub_output_cmd)
            iommu_a = shell_utils.get_cpu_iommu_kernel_arg(self.hypervisor_ip)
            kernel_args.append(iommu_a)
            if result:
                for arg in kernel_args:
                    if arg not in result:
                        test_result.append("The kernel args are missing - {}"
                                           .format(arg))
            else:
                test_result.append("Kernel args: no output received")

        test_result = '\n'.join(test_result)
        self.assertEmpty(test_result, test_result)

    def test_power_saving_tuned_profile(self, test='power_save_tuned_profile'):
        """Test tuned profile for power saving

        The test checks that the tuned profile for power saving is save
        the power on compute nodes.
        """
        if CONF.nfv_plugin_options.target_hypervisor:
            self.hypervisor_ip = \
                self._get_hypervisor_ip_from_undercloud(
                    hyper_name=CONF.nfv_plugin_options.target_hypervisor)
        else:
            self.hypervisor_ip = self._get_hypervisor_ip_from_undercloud()[0]
        self.assertNotEmpty(self.hypervisor_ip, "No hypervisor found")

        data = eval(CONF.nfv_plugin_options.idrac_data)

        hypervisor = data['nodes'][0]
        self.assertNotEmpty(hypervisor, "'compute-0' not found")
        powersave_profile = CONF.nfv_plugin_options.powersave_profile

        client = RedfishClient(
            hypervisor['pm_addr'],
            hypervisor['pm_user'],
            hypervisor['pm_password']
        )
        client.connect()

        # create a VM to make sure it works properly with workload
        hypervisors = \
            self.os_admin.hypervisor_client.list_hypervisors()['hypervisors']
        # take first element of hypervisor list by default
        target_hypervisor = hypervisors[0]
        if CONF.nfv_plugin_options.target_hypervisor:
            # if target_hypervisor provided look for it in hypervisor list
            target_hypervisor = [
                h for h in hypervisors if h['hypervisor_hostname']
                == CONF.nfv_plugin_options.target_hypervisor][0]

        kwargs = {
            'availability_zone': {
                'hyper_hosts': [target_hypervisor['hypervisor_hostname']]
            }
        }
        self.create_and_verify_resources(test=test, **kwargs)

        # baseline power consumption
        # make sure that the tuned profile is not the powersave profile
        active_profile_cmd = "sudo tuned-adm active | awk '{print $4}'"
        active_profile = shell_utils.run_command_over_ssh(
            self.hypervisor_ip, active_profile_cmd).strip('\n')

        if active_profile == powersave_profile:
            switch_profile_cmd = "sudo tuned-adm profile cpu-partitioning"
            shell_utils.run_command_over_ssh(
                self.hypervisor_ip, switch_profile_cmd).strip('\n')
            time.sleep(45)

        # get the baseline power consumption
        baseline_power = client.get_power_state()

        # configure powersave tuned profile to use max_power_state=C6
        source_file = '/etc/tuned/cpu-partitioning-variables.conf'
        dest_file = '/etc/tuned/cpu-partitioning-powersave-variables.conf'

        # copy the vars to the powersave file
        extract_cores_cmd = (
            "grep '^isolated_cores=' " + source_file + " | grep -v '^#'"
        )
        isolated_cores = shell_utils.run_command_over_ssh(
            self.hypervisor_ip, extract_cores_cmd).strip('\n')
        replace_cores_cmd = f"sudo sed -i '/^isolated_cores=/c\\" \
                            f"{isolated_cores}' {dest_file}"
        shell_utils.run_command_over_ssh(
            self.hypervisor_ip, replace_cores_cmd).strip('\n')

        # enable the max_power_state=C6
        new_line = 'max_power_state=cstate.name:C6|140\n'
        cmd = f"sudo sed -i '/max_power_state=/c\\{new_line}'" \
              f" {dest_file}"
        shell_utils.run_command_over_ssh(
            self.hypervisor_ip, cmd).strip('\n')

        # change the tuned profile to power saving
        change_profile_cmd = f"sudo tuned-adm profile " \
                             f"{powersave_profile}"
        shell_utils.run_command_over_ssh(
            self.hypervisor_ip, change_profile_cmd).strip('\n')
        time.sleep(45)

        # get the power consumption - after the tuned profile change
        powersave_power = client.get_power_state()

        # change the tuned profile to be as it was
        cmd = f"sudo tuned-adm profile {active_profile}"
        shell_utils.run_command_over_ssh(self.hypervisor_ip,
                                         cmd).strip('\n')
        client.disconnect()

        # check that the power consumption is lower with the powersave profile
        self.assertGreater(
            baseline_power, powersave_power,
            "Power consumption not reduced with powersave profile")

    def test_mtu_ping_test(self, test='test-ping-mtu'):
        """Test MTU by pinging instance gateway

        The test boots and instance, connects to the instance by ssh and
        pings the network gateway address with the appropriate MTU size.

        Note - The size of the mtu discovered automatically from the
               running environment. The value may differ between deployments.
               Custom mtu size could be provided wia the plugin defaults.

        :param test: Test name from the config file
        :param mtu: Size of the mtu to check
        """
        # TODO(skramaja): Need to check if it is possible to execute ping
        #                 inside the guest VM using network namespace
        self.assertTrue(self.fip, "Floating IP is required for mtu test")

        kwargs = {}
        if CONF.nfv_plugin_options.target_hypervisor:
            hypervisor = CONF.nfv_plugin_options.target_hypervisor
            kwargs = {
                'srv_details': {
                    0: {'availability_zone': 'nova:{}'.format(hypervisor)}
                }
            }
        servers, key_pair = self.create_and_verify_resources(test=test,
                                                             **kwargs)

        if CONF.nfv_plugin_options.instance_def_gw_mtu:
            mtu = CONF.nfv_plugin_options.instance_def_gw_mtu
        else:
            mtu = self.discover_mtu_network_size(fip=servers[0]['fip'])
        LOG.info('Set {} mtu for the test'.format(mtu))

        routers = self.os_admin.routers_client.list_routers()['routers']
        for router in routers:
            if router['external_gateway_info'] is not None:
                gateway = router['external_gateway_info'][
                    'external_fixed_ips'][0]['ip_address']
                break
        else:
            raise ValueError('The gateway of given network does not exists. '
                             'Please assign it and re-run.')

        ssh_source = self.get_remote_client(servers[0]['fip'],
                                            username=self.instance_user,
                                            private_key=key_pair[
                                                'private_key'])
        LOG.info('Execute ping test command')
        out = ssh_source.exec_command('ping -c 1 -M do -s %d %s' % (mtu,
                                                                    gateway))
        msg = "MTU Ping test failed - check your environment settings"
        self.assertTrue(out, msg)
        LOG.info('The {} test passed.'.format(test))

    def test_cold_migration(self, test='cold-migration'):
        """Test cold migration

        The test shuts down the instance, migrates it to a different
        hypervisor and brings it up to verify resize state.
        """

        kwargs = {}
        if CONF.nfv_plugin_options.target_hypervisor:
            hypervisor = CONF.nfv_plugin_options.target_hypervisor
            kwargs = {
                'srv_details': {
                    0: {'availability_zone': 'nova:{}'.format(hypervisor)}
                }
            }
        servers, key_pair = self.create_and_verify_resources(test=test,
                                                             **kwargs)

        LOG.info('Starting the cold migration.')
        self.os_admin.servers_client. \
            migrate_server(server_id=servers[0]['id'])
        waiters.wait_for_server_status(self.os_admin.servers_client,
                                       servers[0]['id'], 'VERIFY_RESIZE')
        LOG.info('Confirm instance resize after the cold migration.')
        self.os_admin.servers_client.confirm_resize_server(
            server_id=servers[0]['id'])
        LOG.info('Verify instance connectivity after the cold migration.')
        self.check_instance_connectivity(ip_addr=servers[0]['fip'],
                                         user=self.instance_user,
                                         key_pair=key_pair['private_key'])
        succeed = True

        msg = "Cold migration test id failing. Check your environment settings"
        self.assertTrue(succeed, msg)
        LOG.info('The cold migration test passed.')

    def test_emulatorpin(self, test='emulatorpin'):
        """Test emulatorpin on the running instance vs nova configuration

        The test compares emulatorpin value from the dumpxml of the running
        instance with values of the overcloud nova configuration.

        Note - The test suit only for RHOS version 14 and up, since the
               emulatorpin feature was implemented only in version 14.
        """

        kwargs = {}
        if CONF.nfv_plugin_options.target_hypervisor:
            hypervisor = CONF.nfv_plugin_options.target_hypervisor
            kwargs = {
                'srv_details': {
                    0: {'availability_zone': 'nova:{}'.format(hypervisor)}
                }
            }
        servers, key_pair = self.create_and_verify_resources(test=test,
                                                             **kwargs)

        config_path = '/var/lib/openstack/config/nova' \
                      '/04-cpu-pinning-nova.conf'
        check_section = 'compute'
        check_value = 'cpu_shared_set'

        for srv in servers:
            LOG.info('Test emulatorpin for the {} instance'.format(srv['fip']))
            return_value = self. \
                compare_emulatorpin_to_overcloud_config(srv,
                                                        srv['hypervisor_ip'],
                                                        config_path,
                                                        check_section,
                                                        check_value)
            self.assertTrue(return_value, 'The emulatorpin test failed. '
                                          'The values of the instance and '
                                          'nova does not match.')
        LOG.info('The {} test passed.'.format(test))
