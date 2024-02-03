#!/bin/bash
exec >  >(tee -ia installClusterShell_$(date "+%Y%m%d%H%M%S").log)
exec 2> >(tee -ia installClusterShell_$(date "+%Y%m%d%H%M%S").log >&2)

echo
echo '##############################################'
echo '#                                            #'
echo '# Welcome to the ClusterShell auto-installer #'
echo '# for Linux.                                 #'
echo '# Last updated 29/08/2021.                   #'
echo '# Note: You will be prompted to write the    #'
echo '# Splunk Web admin password twice.           #'
echo '#                                            #'
echo '##############################################'

PASSWORD=

while [ ! $PASSWORD ]
   do
      echo -e "\e[1;33m### Please enter the root password for all Splunk instances ? \e[0m"
      stty -echo
      read PASSWORD
      stty echo
   done

if [[ ! "$(grep splunk-cm /etc/hosts)" ]]; then
cat  <<EOT >>/etc/hosts
192.168.189.55	splunk-cm
192.168.189.50	splunk-sh
192.168.189.71  splunk-idx1
192.168.189.72  splunk-idx2
192.168.189.73  splunk-idx3
192.168.189.66	splunk-hf1
192.168.189.67 splunk-hf2
192.168.189.60  splunk-ds


EOT
fi

yum install vim -y
#rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
yum install epel-release -y
yum install clustershell -y
yum install sshpass -y
 
cat  <<EOT >/etc/clustershell/groups.d/local.cfg
cm: splunk-cm
idx: splunk-idx[1-3]
sh: splunk-sh
hf: splunk-hf[1-2]
all: splunk-cm splunk-idx[1-3] splunk-sh splunk-hf[1-2] splunk-ds

EOT

clush -O ssh_path="sshpass -p '$PASSWORD' ssh" -O ssh_options='-oBatchMode=no -oStrictHostKeyChecking=no' -l root -a echo hello
[[ ! -f /root/.ssh/id_rsa ]] && clush -O ssh_path="sshpass -p '$PASSWORD' ssh" -O ssh_options='-oBatchMode=no -oStrictHostKeyChecking=no' -l root -a -B 'ssh-keygen -t rsa -N "" -f /root/.ssh/id_rsa' || echo RSA Key already exists!!
cat /root/.ssh/id_rsa.pub | clush -O ssh_path="sshpass -p '$PASSWORD' ssh" -O ssh_options='-oBatchMode=no -oStrictHostKeyChecking=no' -l root -a -b 'cat - >>/root/.ssh/authorized_keys; chmod 600 /root/.ssh/authorized_keys'




