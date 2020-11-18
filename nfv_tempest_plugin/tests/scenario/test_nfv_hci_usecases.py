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

from nfv_tempest_plugin.tests.common import shell_utilities as shell_utils
from nfv_tempest_plugin.tests.scenario import base_test
from oslo_log import log as logging
from tempest import config

CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class TestHciScenarios(base_test.BaseTest):
    def __init__(self, *args, **kwargs):
        super(TestHciScenarios, self).__init__(*args, **kwargs)
        self.hypervisor_ip = None
        self.image_ref = CONF.compute.image_ref

    def setUp(self):
        """Set up a single tenant with an accessible server.

        If multi-host is enabled, save created server uuids.
        """
        super(TestHciScenarios, self).setUp()
        # pre setup creations and checks read from config files

    def test_volume_in_hci_nfv_setup(self, test='nfv_hci_basic_volume'):
        """Test attaches the volume to the instance and writes it.

        Also writing the content into the instance volume.

        :param test: Test name from the config file
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        volume_id = self.create_volume()
        attachment = self.attach_volume(servers[0], volume_id)
        self.assertIn('device', attachment)
        ssh_source = self.get_remote_client(servers[0]['fip'],
                                            username=self.instance_user,
                                            private_key=key_pair[
                                                'private_key'])
        LOG.info('Execute write test command')
        out = ssh_source.exec_command(
            'sudo dd if=/dev/zero of=/dev/vdb bs=4096k count=256 oflag=direct')
        self.assertEmpty(out)
        LOG.info('The {} test passed.'.format(test))

    def test_boot_instance_with_volume_in_hci_nfv_setup(
            self, test='nfv_hci_instance_volume'):
        """Test creates a instance with the volume and writes it.

        Also writing the content into the instance volume.

        :param test: Test name from the config file
        """
        volume = self.create_volume()
        block_device_mapping = [{'device_name': 'vdb',
                                 'volume_id': volume['id'],
                                 'delete_on_termination': False}]
        servers, key_pair = self.create_and_verify_resources(
            test=test, block_device_mapping=block_device_mapping)
        ssh_source = self.get_remote_client(servers[0]['fip'],
                                            username=self.instance_user,
                                            private_key=key_pair[
                                                'private_key'])
        LOG.info('Execute write test command')
        out = ssh_source.exec_command(
            'sudo dd if=/dev/zero of=/dev/vdb bs=4096k count=256 oflag=direct')
        self.assertEmpty(out)
        LOG.info('The {} test passed.'.format(test))

    def test_volume_using_img_in_hci_nfv_setup(
            self, test='nfv_hci_image_volume'):
        """Test attaches the volume to the instance and writes it.

        Also writing the content into the instance volume.

        :param test: Test name from the config file
        """
        servers, key_pair = self.create_and_verify_resources(test=test)
        volume_id = self.create_volume(imageRef=self.image_ref)
        attachment = self.attach_volume(servers[0], volume_id)
        self.assertIn('device', attachment)
        ssh_source = self.get_remote_client(servers[0]['fip'],
                                            username=self.instance_user,
                                            private_key=key_pair[
                                                'private_key'])
        LOG.info('Execute write test command')
        out = ssh_source.exec_command(
            'sudo dd if=/dev/zero of=/dev/vdb bs=4096k count=256 oflag=direct')
        self.assertEmpty(out)
        LOG.info('The {} test passed.'.format(test))

    def test_ceph_health_status_in_hci_nfv_setup(
            self, test='nfv_hci_ceph_health'):
        """Test ceph health status.

        :param test: Test name from the config file
        """
        LOG.info('Execute ceph health status test command')
        hyper_kwargs = {'shell': '/home/stack/stackrc'}
        controller_ip = shell_utils.\
            get_controllers_ip_from_undercloud(**hyper_kwargs)[0]
        cmd = "sudo docker exec ceph-mon-`hostname` ceph -s | grep health | "\
              "cut -d':' -f2 | sed 's/^[ \t]*//;s/[ \t]*$//'"
        result = shell_utils.\
            run_command_over_ssh(controller_ip, cmd).replace("\n", "")
        self.assertEqual(result, 'HEALTH_OK')
        LOG.info('The {} test passed.'.format(test))
