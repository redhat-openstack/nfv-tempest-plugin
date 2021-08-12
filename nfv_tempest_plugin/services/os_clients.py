from nfv_tempest_plugin.services.heat_client import HeatClient
from nfv_tempest_plugin.services.keystone_client import KeystoneClient
from nfv_tempest_plugin.services.nova_client import NovaClient


class OsClients(HeatClient, NovaClient):
    @classmethod
    def setup_clients(cls):
        super(OsClients).__init__()

    @classmethod
    def setup_keystone_client(cls):
        KeystoneClient.__init__(cls)

    @classmethod
    def setup_nova_client(cls):
        NovaClient.__init__(cls)

    @classmethod
    def setup_heat_client(cls):
        HeatClient.__init__(cls)
