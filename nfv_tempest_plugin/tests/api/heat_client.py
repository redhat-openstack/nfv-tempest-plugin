
from heatclient.client import Client
from nfv_tempest_plugin.services.keystone_client import KeystoneClient
from tempest import config

CONF = config.CONF


class HeatClient(KeystoneClient):
    @classmethod
    def set_heat_clients(cls):
        super().set_keystone_clients()
        if cls.uc_server_client == 'nova':
            cls.undercloud_heatclient = Client('1',
                                               session=cls
                                               .undercloud_keystone_session)

        cls.overcloud_heatclient = Client('1',
                                          session=cls
                                          .overcloud_keystone_session)
