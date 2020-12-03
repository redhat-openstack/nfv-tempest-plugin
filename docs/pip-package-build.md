## building pip package with setup tools

1. Get python-pip  
RHEL: `$ sudo yum install python3-pip`  
CentOS: `$ sudo yum install python34-setuptools ; sudo easy_install pip`  
Debian/Ubuntu: `$ sudo apt-get install python3-pip`  

2. Get build dependencies:  
`$ pip3.6 install -u setuptools wheel pip`  
 **NOTE:** Please note the version in the setup.cfg file before building 
 not using the correct version will cause pbr to fail the build
3. Build the pip package:  
`$ pytho3.6 setup.py bdist_wheel sdist`
4. After running the build command you will have a wheel file and a tar.gz file in a newly created dist directory. 
You can install via pip3 

5. Register to [pypi](https://pypi.org/)

6. Install twine to upload the packages:  
`$ python3 -m pip install --upgrade twine`

7. Upload the packages to pypi using twine:  
`python3 -m twine upload dist/*`  
 
