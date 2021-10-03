from neutron_tempest_plugin.api import clients as manager
from neutron_tempest_plugin.services.network.json import network_client
from tempest import config
from tempest.lib.services.network import qos_limit_bandwidth_rules_client
from tempest.lib.services.network import qos_minimum_bandwidth_rules_client

CONF = config.CONF


class Manager(manager.Manager):
    def __init__(self, credentials=None, service=None):
        super(Manager, self).__init__(credentials=credentials)
        self.network_client_v2 = network_client.NetworkClientJSON(
            self.auth_provider,
            CONF.network.catalog_type,
            CONF.network.region or CONF.identity.region,
            endpoint_type=CONF.network.endpoint_type,
            build_interval=CONF.network.build_interval,
            build_timeout=CONF.network.build_timeout,
            **self.default_params)

        self.qos_limit_bandwidth_rules_client = \
            qos_limit_bandwidth_rules_client.QosLimitBandwidthRulesClient(
                self.auth_provider,
                CONF.network.catalog_type,
                CONF.network.region or CONF.identity.region,
                endpoint_type=CONF.network.endpoint_type,eeeeeeeeeeeeeeeeeee
                build_interval=CONF.network.build_interval,
                build_timeout=CONF.network.build_timeout,
                **self.default_params)

        self.qos_minimum_bandwidth_rules_client = \
            qos_minimum_bandwidth_rules_client.QosMinimumBandwidthRulesClient(
                self.auth_provider,
                CONF.network.catalog_type,
                CONF.network.region or CONF.identity.region,
                endpoint_type=CONF.network.endpoint_type,
                build_interval=CONF.network.build_interval,
                build_timeout=CONF.network.build_timeout,
                **self.default_params)
