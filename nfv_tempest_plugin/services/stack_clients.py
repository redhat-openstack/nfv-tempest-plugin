
from nfv_tempest_plugin.services.heat_client import HeatClient
from nfv_tempest_plugin.services.keystone_client import KeystoneClient
from nfv_tempest_plugin.services.nova_client import NovaClient


class StackClients(HeatClient, NovaClient):

    @classmethod
    def setup_clients(cls):
        super(StackClients).__init__()

    @classmethod
    def setup_clients_heat(cls):
        HeatClient.__init__(cls)

    @classmethod
    def setup_client_nova(cls):
        NovaClient.__init__(cls)

    @classmethod
    def setup_client_keystone(cls):
        KeystoneClient.__init__(cls)
