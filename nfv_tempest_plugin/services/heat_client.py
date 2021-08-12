from heatclient.client import Client
from nfv_tempest_plugin.services.keystone_client import KeystoneClient
from tempest import config

CONF = config.CONF


class HeatClient(KeystoneClient):
    def __init__(self):
        super(HeatClient, self).__init__()

        self.undercloud_heatclient = Client('1', session=self
                                            .undercloud_keystone_session)

        self.overcloud_heatclient = Client('1', session=self
                                           .overcloud_keystone_session)
