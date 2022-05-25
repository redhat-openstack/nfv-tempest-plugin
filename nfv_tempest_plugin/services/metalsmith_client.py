
from metalsmith import _provisioner
from nfv_tempest_plugin.services.keystone_client import KeystoneClient


class MetalsmithClient(KeystoneClient):
    @classmethod
    def set_metalsmith_clients(cls):
        super().set_keystone_clients()

        if cls.uc_server_client == 'metalsmith':
            cls.metalsmith = _provisioner.Provisioner(
                cloud_region=cls.undercloud_keystone_session.config)
            cls.metalsmith.connection = cls.undercloud_keystone_session

