import os
import getpass

######## CONFIG BEGIN ########
UBUNTU_VERSION = '18.04'
IMAGE_NAME = 'tpm_playground'
######## CONFIG END ##########

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
os.chdir(SCRIPT_DIR)
with open('Dockerfile.in') as f:
    content = f.read()
    content = content.format(username=getpass.getuser(), uid=os.getuid(), UBUNTU_VERSION=UBUNTU_VERSION)
    with open('Dockerfile', 'w') as f2:
        f2.write(content)

os.system('docker build -t {} .'.format(IMAGE_NAME))