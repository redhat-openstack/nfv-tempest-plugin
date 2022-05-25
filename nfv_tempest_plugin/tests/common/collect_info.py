from oslo_log import log as logging
import subprocess

LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class CollectInfo():
    def check_client():
        metalsmith_show = "source ~/stackrc && metalsmith list"
        try:
            subprocess.check_output(['bash', '-c', metalsmith_show])
            return "metalsmith"
        except subprocess.CalledProcessError:
            return "nova"

