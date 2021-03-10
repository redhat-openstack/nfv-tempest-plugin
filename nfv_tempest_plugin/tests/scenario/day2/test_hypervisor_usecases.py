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
from nfv_tempest_plugin.services.heat_client import HeatClient
from nfv_tempest_plugin.services.nova_client import NovaClient
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from paramiko.ssh_exception import NoValidConnectionsError
from tempest.common import waiters
from tempest import config
import threading
import time


CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestHypervisorScenarios(base_test.BaseTest, NovaClient, HeatClient):
    def __init__(self, *args, **kwargs):
        super(TestHypervisorScenarios, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None
        self.exec_info = None

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

    def validate_no_reboot_in_stack_update(self, stack_name='overcloud',
                                           hypervisors_ip=False):
        """test node didn't reboot meanwhile stack update

        quries heat api and validate that no reboot
        occuered durring stack update
        """
        LOG.info('Started validateing no reboot meanwhile stack update.')
        LOG.info('Fetching stack update start and end from heat API')
        for event in self.undercloud_heatclient.events.list(stack_name):
            if event.resource_status_reason == 'Stack UPDATE started':
                update_start = datetime.datetime.strptime(event.event_time,
                                                          '%Y-%m-%dT%H:%M:%SZ')
            elif event.resource_status_reason ==\
                'Stack UPDATE completed successfully':
                update_end = datetime.datetime.strptime(event.event_time,
                                                        '%Y-%m-%dT%H:%M:%SZ')
        # TODO(eshulman) replace with novaclient
        if not hypervisors_ip:
            LOG.info('Fetching overcloud hypervisors ip addresses')
            hyper_kwargs = {'shell':
                            CONF.nfv_plugin_options.undercloud_rc_file}
            hypervisors_ip = self._get_hypervisor_ip_from_undercloud(
                **hyper_kwargs)

        rebooted_hypervisors = []
        for hypervisor in hypervisors_ip:
            # TODO(eshulman) replace with overcloud novaclient Client.uptime
            try:
                last_reboot = datetime.datetime.strptime(
                    shell_utils.run_command_over_ssh(
                        hypervisor, 'uptime -s'), '%Y-%m-%d %H:%M:%S\n')
            except NoValidConnectionsError:
                LOG.info('One or more of the hypervisor is '
                         'unreachable via ssh please make sure all '
                         'hypervisors are up')
                raise NoValidConnectionsError

            if last_reboot <= update_end and last_reboot >= update_start:
                rebooted_hypervisors.append(hypervisor)

        self.assertEmpty(rebooted_hypervisors,
                         'Computes with the following {} ip address rebooted '
                         'durring the update'
                         .format(rebooted_hypervisors))

    def reboot_hypervisor_and_wait(self, hypervisor):
        """reboots hypervisor and wait for it to be up

        :param hypervisor: novaclient hypervisor object
        :param novaclient_overcloud: novaclient object with a session
                                     to overcloud
        :param novaclient_undercloud: novaclient object with a session
                                     to undercloud
        """
        relapsed_time = 90
        hypervisor_name = hypervisor.hypervisor_hostname.split('.')[0]
        hypervisor = self.overcloud_hypervisor_to_undecloud_server(hypervisor)

        LOG.info('Rebooting: {}'.format(hypervisor_name))
        hypervisor.reboot()

        # buffer for hypervisor status to update
        time.sleep(relapsed_time)
        LOG.info('############## {}'.format(self.novaclient_overcloud.hypervisors.search(
                hypervisor_name)[0].state))
        while 'down' == self.novaclient_overcloud.hypervisors.search(
                hypervisor_name)[0].state:
            time.sleep(30)
            relapsed_time = relapsed_time + 10
            if (relapsed_time >= CONF.nfv_plugin_options
                .hypervisor_wait_timeout):
                LOG.debug('{} reboot had timed out'.format(hypervisor_name))
                raise TimeoutError
                import sys
                self.exec_info = sys.exc_info()

        else:
            LOG.info('{} is up'.format(hypervisor_name))

    def validate_kargs(self, ip):
        """validates kernal args are as expected

        :param ip: ip adress of a server to validate
        """
        LOG.info('Validating kargs are competable')
        # TODO(eshulman) replace with a heat query
        expected_args = CONF.nfv_plugin_options.kernel_args.split(' ')
        try:
            cmdline = shell_utils.run_command_over_ssh(ip,
                                                'cat /proc/cmdline').split(' ')
        except Exception as err:
            import sys
            self.exec_info = sys.exc_info()
            raise err

        for arg in expected_args:
            self.assertIn(arg, cmdline,
                          'kernel arguments did not update after node reboot')

    def reboot_validate_kernel_args(self, hypervisor):
        """reboots and validates kernal args are as expected

        :param hypervisor: novaclient hypervisor object
        :param novaclient_overcloud: novaclient object with a
                                     session to overcloud
        """
        self.reboot_hypervisor_and_wait(hypervisor)
        hypervisor_ip = self.novaclient_undercloud.servers.list(
            search_opts={'hostname':
                         hypervisor.hypervisor_hostname
                         .split('.')[0]})[0].networks['ctlplane'][0]
        self.validate_kargs(hypervisor_ip)

    def multithread_wraper(self, iteratable, target, args=()):
        """a warpper to run multithread and wait for all threads to complete

        this function is made to allow running multithreaded tasks on a list
        of items the function sends the item to the function as first
        parameter and accepts only args (by placement) which means that every
        function that is called via this should accept the item as first
        parameter
        :param iteratable: an iteratable object
        :param target: the function called via the therad
        :param args: a tuple containing parameters to send to the target
        """
        threads = []
        for item in iteratable:
            # create a list of callable threads
            threads.append(threading.Thread(
                           target=target,
                           args=(item, *args)))

        LOG.info('Starting multithread call for {}'.format(target))
        for theread in threads:
            # start all threads
            theread.start()

        LOG.info('Waiting for all threads to complete')
        for theread in threads:
            # wait for all threads to complete
            theread.join()

        if self.exec_info:
            raise self.exec_info[1].with_traceback(self.exec_info[2])

    def get_old_and_new_compute(self, stack_name='overcloud',
                                compute_prefix='compute'):
        """creates two lists containing computes from before and after update

        :param stack_name: the name of the overcloud stack
        :param novaclient_undercloud: novaclient object with a session
                                      to the undercloud
        :return old_compute: a list containing all computes from before the
                             scale out
        :return new_compute: a list containing all computes from after the
                             scale out
        """
        old_compute = []
        new_compute = []

        for event in self.undercloud_heatclient.events.list(stack_name):
            if event.resource_status_reason == 'Stack UPDATE started':
                update_start = datetime.datetime.strptime(event.event_time,
                                                          '%Y-%m-%dT%H:%M:%SZ')
        if not update_start:
            raise NameError('the stack was not updated')

        for compute in self.novaclient_undercloud.servers.list(
            search_opts={'hostname': compute_prefix}):
            if datetime.datetime.strptime(compute.created,
                                          '%Y-%m-%dT%H:%M:%SZ') < update_start:
                old_compute.append(compute.networks['ctlplane'][0])
            else:
                new_compute.append(compute.networks['ctlplane'][0])

        return old_compute, new_compute

    def test_scale_out_kernelargs_hypervisor_reboot(self, test='scale_out'
                                                    '_kernelargs'):
        """test reather hypervisors rebooted and kargs changed in scale out

        tests that old hypervisor didn't reboot in scale out and that all
        hypervisor have all expected kargs
        """
        super().set_nova_clients()
        super().set_heat_clients()
        LOG.info('test {} started'.format(test))
        old_compute, new_compute = self.get_old_and_new_compute()
        self.validate_no_reboot_in_stack_update(hypervisors_ip=old_compute)
        self.multithread_wraper(new_compute, self.validate_kargs)
        self.multithread_wraper(self.novaclient_overcloud.hypervisors.list(),
                                target=self.reboot_validate_kernel_args)

    def test_stack_update_kernel_args_hypervisor_reboot(self,
                                                        test='stack_'
                                                        'update_kernelargs'):
        """test reather hypervisors rebooted and kargs changed

        test reather hypervisors rebooted meanwhile update and validates kargs
        are as expected
        """
        super().set_nova_clients()
        super().set_heat_clients()
        LOG.info('test {} started'.format(test))
        self.validate_no_reboot_in_stack_update()
        self.multithread_wraper(self.novaclient_overcloud.hypervisors.list(),
                                target=self.reboot_validate_kernel_args)
