from nfv_tempest_plugin.services.heat_client import HeatClient
from nfv_tempest_plugin.services.nova_client import NovaClient


class OsClients(HeatClient, NovaClient):
    def __init__(self):
        super().set_heat_clients()
        super().set_nova_clients()
