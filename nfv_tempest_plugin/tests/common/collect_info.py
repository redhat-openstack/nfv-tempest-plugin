from oslo_log import log as logging
import re
import subprocess

LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class CollectInfo():
    def check_client():
        """Return the undercloud show supported undercloud server api"""

        output = subprocess.check_output(['cat', '/etc/rhosp-release'])
        rhosp_version = int(re.findall(b'\d+', output)[0])
        if rhosp_version >= 17:
            return 'metalsmith'
        return 'nova'
