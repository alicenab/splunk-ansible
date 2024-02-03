#!/bin/bash

 echo ''
 echo '##############################################'
 echo '#                                            #'
 echo '# Welcome to the Splunk Cluster Uninstalle   #'
 echo '# for CentOS/Ubuntu                          #'
 echo '# Last updated 15/05/2022.                   #'
 echo '#                                            #'
 echo '##############################################'
 echo ''

while getopts p:h flag
do
    case "${flag}" in
        p) INSTALL_PATH=${OPTARG};;
        h) HELP=Yes;;
    esac
done

if [ $HELP ]; then
   echo "
#####################################################################################
# Command Line Usage 
# p) INSTALL_PATH (/opt, /data etc.)
# h) Help 

Sample;

./uninstallSplunkCluster.sh -p /data

#####################################################################################"
   exit 0
fi

clush -a -c uninstallSplunk.sh --dest /tmp
clush -a bash /tmp/uninstallSplunk.sh -p $INSTALL_PATH

