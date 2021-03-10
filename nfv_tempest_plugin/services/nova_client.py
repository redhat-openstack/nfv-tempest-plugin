
from novaclient.client import Client
import keystone_client
from tempest import config
from nfv_tempest_plugin.services.keystone_client import KeystoneClient

CONF = config.CONF

class NovaClient(KeystoneClient):
    def __init__(self):
        super(NovaClient, self).__init__()

        self.novaclient_overcloud = Client(version=CONF
                                          .compute.max_microversion,
                                          session=self
                                          .overcloud_keystone_session)
        self.novaclient_undercloud = Client(version=CONF
                                           .compute.max_microversion,
                                           session=self
                                           .undercloud_keystone_session)

    def overcloud_hypervisor_to_undecloud_server(self, hypervisor):
        """takes an hypervisor object and
        find its related server in the undercloud

        :param hypervisor: nova client hypervisor object
        :return nova client server object
        """
        hypervisor_name = hypervisor.hypervisor_hostname.split('.')[0]
        return self.novaclient_undercloud.servers.list(
                    search_opts={'hostname': hypervisor_name})[0]

