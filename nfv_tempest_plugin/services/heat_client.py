
from heatclient.client import Client
from nfv_tempest_plugin.services.keystone_client import KeystoneClient
from tempest import config

CONF = config.CONF


class HeatClient(KeystoneClient):
    # due to python2 backword competability I'm changing 
    # cls to self should be changed back as soon as we are 
    # migrating to use only python3
    @classmethod
    def set_heat_clients(self):
        super().set_keystone_clients()

        self.undercloud_heatclient = Client('1',
                                           session=self
                                           .undercloud_keystone_session)

        self.overcloud_heatclient = Client('1',
                                          session=self
                                          .overcloud_keystone_session)
