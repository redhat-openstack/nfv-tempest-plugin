from oslo_log import log as logging
from tempest import test
from tempest import config
from tempest.lib import exceptions as lib_exc
from tempest import *

LOG = logging.getLogger(__name__)
CONF = config.CONF


class TestNfvPlugin(test.scenario.manager.ScenarioTest):
   # Use set up to instantiate parent class and apply configurations
   def setUp(self):
       """Set up a single tenant with an accessible server.
              If multi-host is enabled, save created server uuids.
              """
       self.servers = []
       super(TestNfvPlugin, self).setUp()
       # Example for pre setup creations and checks read from config files
       self.image_ref = CONF.compute.image_ref  ## as explained earlier
       self.flavor_ref = CONF.compute.flavor_ref  ## as explained earlier

   def test_server_nfv_plugin(self):  ## we define the test_server_basicops method
       ##using the create_server method with our variables, as we described earlier
       self.instance = self.create_server(image_id=self.image_ref,
                                          flavor=self.flavor_ref, wait_until='ACTIVE')
       ##Incase logger defined outside of your class print to log message as the following
       LOG.info("HELLO")

