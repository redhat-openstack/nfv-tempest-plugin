
import datetime
from nfv_tempest_plugin.services.os_clients import OsClients
from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from paramiko.ssh_exception import NoValidConnectionsError
from tempest import config
import time

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class Day2Manager(base_test.BaseTest):
    def __init__(self):
        super().__init__()
        self.os_client = OsClients()

    def validate_no_reboot_in_stack_update(self, stack_name='overcloud',
                                           hypervisors_ip=False):
        """test node didn't reboot meanwhile stack update

        quries heat api and validate that no reboot
        occuered durring stack update
        """
        LOG.info('Started validateing no reboot meanwhile stack update.')
        LOG.info('Fetching stack update start and end from heat API')
        for event in self.os_client\
            .undercloud_heatclient.events.list(stack_name):
            if event.resource_status_reason == 'Stack UPDATE started':
                update_start = datetime.datetime.strptime(event.event_time,
                                                          '%Y-%m-%dT%H:%M:%SZ')
            elif event.resource_status_reason ==\
                'Stack UPDATE completed successfully':
                update_end = datetime.datetime.strptime(event.event_time,
                                                        '%Y-%m-%dT%H:%M:%SZ')
        if not hypervisors_ip:
            LOG.info('Fetching overcloud hypervisors ip addresses')
            hyper_kwargs = {'shell':
                            CONF.nfv_plugin_options.undercloud_rc_file}
            hypervisors_ip = self._get_hypervisor_ip_from_undercloud(
                **hyper_kwargs)

        rebooted_hypervisors = []
        for hypervisor in hypervisors_ip:
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
        hypervisor = self.os_client\
            .overcloud_hypervisor_to_undecloud_server(hypervisor)

        LOG.info('Rebooting: {}'.format(hypervisor_name))
        hypervisor.reboot()

        # buffer for hypervisor status to update
        time.sleep(relapsed_time)
        while 'down' == self.os_client.novaclient_overcloud.hypervisors.search(
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
                                                       'cat /proc/cmdline')\
                .split(' ')
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
        hypervisor_ip = self.os_client.novaclient_undercloud.servers.list(
            search_opts={'hostname':
                         hypervisor.hypervisor_hostname
                         .split('.')[0]})[0].networks['ctlplane'][0]
        self.validate_kargs(hypervisor_ip)

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

        for event in self.os_client\
            .undercloud_heatclient.events.list(stack_name):
            if event.resource_status_reason == 'Stack UPDATE started':
                update_start = datetime.datetime.strptime(event.event_time,
                                                          '%Y-%m-%dT%H:%M:%SZ')
        if not update_start:
            raise NameError('the stack was not updated')

        for compute in self.os_client.novaclient_undercloud.servers.list(
            search_opts={'hostname': compute_prefix}):
            if datetime.datetime.strptime(compute.created,
                                          '%Y-%m-%dT%H:%M:%SZ') < update_start:
                old_compute.append(compute.networks['ctlplane'][0])
            else:
                new_compute.append(compute.networks['ctlplane'][0])

        return old_compute, new_compute
