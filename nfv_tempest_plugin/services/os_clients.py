from nfv_tempest_plugin.services.heat_client import HeatClient
from nfv_tempest_plugin.services.nova_client import NovaClient
from nfv_tempest_plugin.services.swift_client import SwiftClient


class OsClients(HeatClient, NovaClient, SwiftClient):
    def __init__(self):
        super().set_heat_clients()
        super().set_nova_clients()
        super().set_swift_clients()
