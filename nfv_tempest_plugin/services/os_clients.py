
from nfv_tempest_plugin.services.heat_client import HeatClient
from nfv_tempest_plugin.services.nova_client import NovaClient


class OsClients(HeatClient, NovaClient):
    def setup_clients(self, cls):
        super().set_heat_clients(cls)
        super().set_nova_clients(cls)
