from oslo_log import log as logging
import subprocess

LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class CollectInfo():
    def check_client():
        """Return the undercloud show supported undercloud server api"""
        nova_show = "source ~/stackrc && nova list"
        try:
            subprocess.check_output(['bash', '-c', nova_show])
            return "nova"
        except subprocess.CalledProcessError:
            return "metalsmith"
