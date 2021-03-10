# Copyright 2020 Red Hat, Inc.
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

import datetime
from heatclient.client import Client
from keystoneauth1.identity import v3
from keystoneauth1 import session
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from novaclient.client import novaClient
from oslo_log import log as logging
from tempest.common import waiters
from tempest import config
import threading
import time


CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestHypervisorScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestHypervisorScenarios, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None

        undercloud_rc = self.parse_rc_file(
            CONF.nfv_plugin_options.undercloud_rc_file)

        self.undercloud_keystone_session = session.Session(auth=v3.Password(
            auth_url=undercloud_rc['OS_AUTH_URL'],
            username=undercloud_rc['OS_USERNAME'],
            password=undercloud_rc['OS_PASSWORD'],
            project_name=undercloud_rc['OS_PROJECT_NAME'],
            user_domain_name=undercloud_rc[
                'OS_USER_DOMAIN_NAME'],
            project_domain_name=undercloud_rc[
                'OS_PROJECT_DOMAIN_NAME']))
        self.overcloud_keystone_session = session.Session(auth=v3.Password(
            auth_url=CONF.identity.uri,
            username=CONF.auth.admin_username,
            password=CONF.auth.admin_password,
            project_name=CONF.auth.admin_project_name,
            user_domain_name=CONF.auth.admin_domain_name,
            project_domain_name=CONF.auth.admin_domain_name))

    def setUp(self):
        "Setup a single tenant with an accessible server"
        super(TestHypervisorScenarios, self).setUp()

    def test_hypervisor_reboot(self, test='hypervisor_reboot'):
        """Test functionality of DPDK and SRIOV after hypervisor reboot

        The test will spawn up an instance and then will
        reboot the hypervisor that holds the test instance.
        After hypervisor boot up, the instance will be started
        and tested for the accessability.
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        LOG.info("Locate instance hypervisor")
        srv_hyper_name = self.os_admin.servers_client.show_server(
            servers[0]['id'])['server']['OS-EXT-SRV-ATTR:host']
        srv_on_hyper = self.hypervisor_client.list_servers_on_hypervisor(
            srv_hyper_name)['hypervisors'][0]['servers']
        LOG.info("Shut down the instances and reboot the hypervisor "
                 "the instance resides on")
        # In order the prevent instances file system corruption,
        # shut down the instance.
        for srv in srv_on_hyper:
            self.servers_client.stop_server(srv['uuid'])
            waiters.wait_for_server_status(self.servers_client, srv['uuid'],
                                           'SHUTOFF')
        shell_utils.run_command_over_ssh(servers[0]['hypervisor_ip'],
                                         "sudo reboot")
        # Reboot of the baremetal hypervisor takes time.
        # In order to not confuse the test, look for the hypervisor status
        # "down" and then "up".
        hyper_rebooted = False
        timeout_start = time.time()
        timeout_end = CONF.nfv_plugin_options.hypervisor_wait_timeout
        while time.time() < timeout_start + timeout_end:
            time.sleep(10)
            hyper_state = self.hypervisor_client.search_hypervisor(
                srv_hyper_name)['hypervisors'][0]['state']
            if 'down' in hyper_state:
                hyper_rebooted = True
                continue
            if hyper_rebooted and 'up' in hyper_state:
                break
        LOG.info("Hypervisor has been rebooted. Booting up the instances.")
        for srv in srv_on_hyper:
            self.servers_client.start_server(srv['uuid'])
            waiters.wait_for_server_status(self.servers_client, srv['uuid'],
                                           'ACTIVE')
        LOG.info("Check instances connectivity")
        for srv in servers:
            self.check_instance_connectivity(ip_addr=srv['fip'],
                                             user=self.instance_user,
                                             key_pair=key_pair['private_key'])
        LOG.info("The hypervisor reboot test passed.")

    def parse_rc_file(self, rc_file):
        conf = {}
        with open(rc_file, 'r') as rc:
            for line in rc.read().split('\n'):
                if '=' in line:
                    param = line.split('=')
                    conf[param[0].replace('export ', '')] = param[1]
        return conf

    def test_no_reboot_in_stack_update(self, stack_name='overcloud'):
        """test node didn't reboot in upgrade

        quries heat api and validate that no reboot
        occuered durring stack update
        """
        heat_client = Client('1', session=self.undercloud_keystone_session)

        for event in heat_client.events.list(stack_name):
            if event.resource_status_reason == 'Stack UPDATE started':
                update_start = datetime.datetime.strptime(event.event_time,
                                                          '%Y-%m-%dT%H:%M:%SZ')
            elif event.resource_status_reason ==\
                'Stack UPDATE completed successfully':
                update_end = datetime.datetime.strptime(event.event_time,
                                                        '%Y-%m-%dT%H:%M:%SZ')

        hyper_kwargs = {'shell': CONF.nfv_plugin_options.undercloud_rc_file}
        hypervisors_ip = self._get_hypervisor_ip_from_undercloud(
            **hyper_kwargs)

        for hypervisor in hypervisors_ip:
            # TODO(eshulman) replace with overcloud novaclient Client.uptime
            last_reboot = datetime.datetime.strptime(
                shell_utils.run_command_over_ssh(
                    self.hypervisor_ip, 'uptime -s'), '%Y-%m-%d %H:%M:%S')
            self.assertFalse(last_reboot <= update_end
                             and last_reboot >= update_start,
                             'Compute with this {} ip address rebooted'
                             'durring the update'
                             .format(hypervisor))

    def reboot_hypervisor_and_wait(self, hypervisor, novaclient_overcloud):
        novaclient_undercloud = novaClient(CONF.comupte.max_microversion,
                                           self.undercloud_keystone_session)

        hypervisor_name = hypervisor.hypervisor_hostname.split('.')[0]
        hypervisor = novaclient_undercloud.servers.list(
            search_opts={'hostname': hypervisor_name})[0]

        hypervisor.reboot()

        hyper_rebooted = False
        timeout_start = time.time()
        timeout_end = CONF.nfv_plugin_options.hypervisor_wait_timeout
        while time.time() < timeout_start + timeout_end:
            time.sleep(10)
            hyper_state = \
                novaclient_overcloud.hypervisors.search(
                    hypervisor_name)[0].state
            if 'down' in hyper_state:
                hyper_rebooted = True
                continue
            if hyper_rebooted and 'up' in hyper_state:
                break

    def reboot_validate_kernel_args(self, hypervisor, novaclient_overcloud):
        # TODO(eshulman) replace with a heat query
        expected_args = CONF.nfv_plugin_options.kernel_args.split(' ')
        self.reboot_hypervisor_and_wait(hypervisor, novaclient_overcloud)
        cmdline = shell_utils.run_command_over_ssh(self.hypervisor_ip,
                                                   'cat /proc/cmdline')\
            .split(' ')

        for arg in expected_args:
            self.assertIn(arg, cmdline,
                          'krnel arguments did not update after node reboot')

    def multithread_wrap_validate_kernel_args_after_reboot(self):
        threads = []
        novaclient_overcloud = novaClient(CONF.comupte.max_microversion,
                                          self.overcloud_keystone_session)
        for hypervisor in novaclient_overcloud.hypervisors.list():
            threads.append(threading.Thread(
                           target=self.reboot_validate_kernel_args,
                           args=(hypervisor, novaclient_overcloud)))

        for theread in threads:
            theread.start()

        for theread in threads:
            theread.join()

    def test_update_kernel_argshypervisor_reboot(self,
                                                 test='update_kernelargs'):
        self.test_no_reboot_in_stack_update()
        self.multithread_wrap_validate_kernel_args_after_reboot()
