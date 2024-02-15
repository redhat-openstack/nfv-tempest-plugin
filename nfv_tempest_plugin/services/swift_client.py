import swiftclient.client as swift

from nfv_tempest_plugin.services.keystone_client import KeystoneClient
from oslo_log import log as logging
from tempest import config


CONF = config.CONF
LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class SwiftClient(KeystoneClient):
    @classmethod
    def set_swift_clients(cls):
        super().set_keystone_clients()

        cls.overcloud_swift_client = \
            swift.Connection('1', session=cls.overcloud_keystone_session)
