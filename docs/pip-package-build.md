## building pip package with setup tools

1. Get python-pip  
RHEL: `$ sudo yum install python3-pip`  
CentOS: `$ sudo yum install python34-setuptools ; sudo easy_install pip`  
Debian/Ubuntu: `$ sudo apt-get install python3-pip`  

2. Get build dependencies:  
`$ pip3.6 install -u setuptools wheel pip`   
3. Clone nfv-tempest-plugin repo and cd into the cloned directory:  
`$ git clone https://github.com/redhat-openstack/nfv-tempest-plugin.git`  
`$ cd nfv-tempest-plugin`
4. change to the branch/tag you would like to build:  
`$ git checkout <branch>`  
**NOTE:** Please note the version in the setup.cfg file before building the package. The 
version should be in correlation with the tag you are building. Not using the correct
 version will cause pbr to fail the build.
5. Build the pip package:  
`$ pytho3.6 setup.py bdist_wheel sdist`
6. After running the build command you will have a wheel file and a tar.gz file in a newly created dist directory. 
You can install via pip3 

7. Register to [pypi](https://pypi.org/)

8. Install twine to upload the packages:  
`$ python3 -m pip install --upgrade twine`

9. Upload the packages to pypi using twine:  
`python3 -m twine upload dist/*`  
 
