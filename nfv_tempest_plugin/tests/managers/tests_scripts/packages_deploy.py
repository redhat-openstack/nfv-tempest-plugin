#!/bin/env python
# Copyright 2019 Red Hat, Inc.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

# The script is able to install requested pip packages.

import argparse
import logging
import subprocess
import sys

logging.basicConfig(filename='/var/log/messages', filemode='a',
                    format='%(asctime)s %(name)s %(levelname)s: %(message)s',
                    datefmt="%h %d %H:%M:%S", level=logging.INFO)
handler = logging.StreamHandler(sys.stdout)
logger = logging.getLogger("PackagesDeploy")
logger.addHandler(handler)


def execute_shell_command(cmd):
    """Execute shell command

    The subprocess.check_output executes command provided as list.
    If the command will be provided as string, it will be converted to list
    and then executed.
    """
    if not isinstance(cmd, list):
        cmd = cmd.split()
    try:
        logger.info('Execute command: {}'.format(cmd))
        output = subprocess.check_output(cmd)
    except subprocess.CalledProcessError as e:
        logger.info('Command failed: {}'.format(e))
        raise
    return output


def install_pip():
    """Installing pip"""
    logger.info('Checking for pip installed')
    try:
        import pip  # noqa
        logger.info('Pip was found')
    except ImportError:
        logger.info('Pip was not found. Installing.')
        execute_shell_command('curl https://bootstrap.pypa.io/get-pip.py'
                              ' -o /tmp/get-pip.py')
        execute_shell_command('python /tmp/get-pip.py')
        logger.info('Update pip and setuptools to the latest version')
        execute_shell_command('pip install -U pip setuptools')


def install_pip_packages(packages=None):
    """Install pip provided package/s"""
    if packages is None:
        raise ValueError('The pip install has been called, '
                         'but no packages provided.')
    packages_list = packages.split(',')
    packages = ' '.join(packages_list)
    logger.info('Installing {} packages'.format(packages_list))
    execute_shell_command('pip install {}'.format(packages))


def main():
    logger.info('Start package deploy script configuration')
    parser = argparse.ArgumentParser(description='Bootstraping test config '
                                                 'script')
    parser.add_argument('--pip-packages',
                        help='Packages that should be installed by pip. '
                             'Separate multiple packages by comma.',
                        required=False)
    args = parser.parse_args()

    if args.pip_packages:
        install_pip()
        install_pip_packages(args.pip_packages)
    logger.info('Package deploy script configuration completed')


if __name__ == '__main__':
    main()
