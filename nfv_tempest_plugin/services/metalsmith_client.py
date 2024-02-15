
from metalsmith import _provisioner
from nfv_tempest_plugin.services.keystone_client import KeystoneClient


class MetalsmithClient(KeystoneClient):
    @classmethod
    def set_metalsmith_clients(cls):
        super().set_keystone_clients()
