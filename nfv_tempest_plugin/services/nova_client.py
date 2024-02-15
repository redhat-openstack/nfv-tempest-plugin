
from nfv_tempest_plugin.services.keystone_client import KeystoneClient
from novaclient.client import Client
from tempest import config

CONF = config.CONF


class NovaClient(KeystoneClient):
    @classmethod
    def set_nova_clients(cls):
        super().set_keystone_clients()

        cls.novaclient_overcloud = Client(version=CONF
                                          .compute.max_microversion,
                                          session=cls
                                          .overcloud_keystone_session)

    def overcloud_hypervisor_to_undecloud_server(self, hypervisor):
        """take in hypervisor object and find its related undercloud server

        :param hypervisor: nova client hypervisor object
        :return nova client server object
        """
        hypervisor_name = hypervisor.hypervisor_hostname.split('.')[0]
        return self.novaclient_undercloud.servers.list(search_opts={
            'hostname': hypervisor_name})[0]
