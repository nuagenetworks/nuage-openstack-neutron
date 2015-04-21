#!/bin/bash
# 
# Name:
#
# Author:Chao Zhang
# Author:Nicolas Ochem
#
# Email: chao.zhang1@alcatel-lucent.com
#
# Description: This is the nuage build script for build centos rpm packages  
#
# Remove the .git directory if it exists
set -e

################# Handle build metadata #######################################
# we handle nightly builds only for now
OVS_BUILD_NUMBER=$(echo $BUILD_NAME | sed "s/^.*-\(.*\)$/\1/")

################## Generate the python rpm ####################################
PBR_VERSION=${OVS_BUILD_NUMBER} python setup.py bdist_rpm --release="nuage_kilo"

if [[ ! $? -eq 0 ]]
then
    echo "failed to build rpm, exit..."
    exit 1
fi

exit 0
