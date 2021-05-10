
from oslo_log import log as logging
import threading

LOG = logging.getLogger('{} [-] nfv_plugin_test'.format(__name__))


class AsyncUtilsManager():
    def __init__(self):
        self.exec_info = []

    def multithread_iter_wraper(self, iteratable, target, args=()):
        """a warpper to run multithread and wait for all threads to complete

        this function is made to allow running multithreaded tasks on a list
        of items the function sends the item to the function as first
        parameter and accepts only args (by placement) which means that every
        function that is called via this should accept the item as first
        parameter
        :param iteratable: an iteratable object
        :param target: the function called via the therad
        :param args: a tuple containing parameters to send to the target
        """
        threads = []
        for item in iteratable:
            # create a list of callable threads
            threads.append(threading.Thread(
                           target=target,
                           args=(item, args[0::])))

        LOG.info('Starting multithread call for {}'.format(target))
        for theread in threads:
            # start all threads
            theread.start()

        LOG.info('Waiting for all threads to complete')
        for theread in threads:
            # wait for all threads to complete
            theread.join()

        if self.exec_info:
            raise self.exec_info[1].with_traceback(self.exec_info[2])
