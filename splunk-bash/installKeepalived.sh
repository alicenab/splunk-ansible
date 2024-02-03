#!/bin/bash
echo ''
echo '##############################################'
echo '#                                            #'
echo '# Welcome to the Keepalived Installer        #'
echo '# for CentOS/Ubuntu                          #'
echo '# Last updated 29/08/2021.                   #'
echo '#                                            #'
echo '##############################################'
echo ''
#################################################
# Please set virtual_ipaddress.
VIRTUAL_IP=192.168.11.100
# Please set ethernet name for keepalived.
INTERFACE=ens192
# Please set startup state (MASTER/BACKUP).
STATE=MASTER
# Please set virtual_router_id.
VIRTUAL_ROUTER_ID=51
# Please set password for authentication.
PASSWORD=_PASSWORD_
# Please set the syslog path.
DISK_PATH=/data
#################################################
LB=

while getopts v:i:s:P:l:p:r:d:h flag
do
    case "${flag}" in
        v) VIRTUAL_IP=${OPTARG};;
        i) INTERFACE=${OPTARG};;
        s) STATE=${OPTARG};;
        P) PRIORITY=${OPTARG};;
        l) LB=${OPTARG};;
        p) PASSWORD=${OPTARG};;
        r) VIRTUAL_ROUTER_ID=${OPTARG};;
        d) DISK_PATH=${OPTARG};;
        l) LB=${OPTARG};;
        h) HELP=Yes;;
    esac
done

if [ $HELP ]; then
   echo "
#####################################################################################
# Command Line Usage 
# v) VIRTUAL_IP of Keepalived
# i) INTERFACE of Keepalived
# s) STATE of Keepalived on this host, MASTER or BACKUP
# P) PRIOTITY of Keepalived on this host
# p) Auth PASSWORD of this Keepalived service (Max 8 chars)
# r) VIRTUAL_ROUTER_ID of this Keepalived service (0 - 255)
# d) SYSLOG path for disk space check script
# l) LB active or not
# h) Help 

Sample;
MASTER
./installKeepalived.sh -v 127.0.0.127 -i ens33 -s MASTER -p PASSWORD -r 51 -d /opt
BACKUP
./installKeepalived.sh -v 127.0.0.127 -i ens33 -s BACKUP -p PASSWORD -r 51 -d /opt

#####################################################################################"
   exit 0
fi

while [[ ! $VIRTUAL_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]
   do
      echo -e "\e[1;33m### Please enter a valid VIRTUAL_IP of Keepalived ?\e[0m"
      read VIRTUAL_IP
   done
#while ! netstat -i | grep -v Kernel | grep -v Iface | grep -v lo |  awk '{print $1}' | grep $INTERFACE  
while ! ip link show | grep ":\s" | grep -v "lo:" | awk -F': ' {'print $2'} | grep $INTERFACE  
   do
      echo -e "\e[1;33m### Please enter a valid INTERFACE of Keepalived ?\e[0m"
      echo "### Valid Interfaces:"
      ip link show | grep ":\s" | grep -v "lo:" | awk -F': ' {'print $2'}
      read INTERFACE
   done

while [[ ! $STATE == "MASTER" ]] && [[ ! $STATE ==  "BACKUP" ]]
   do
      echo -e "\e[1;33m### Please enter the STATE of Keepalived on this host, MASTER or BACKUP ?\e[0m"
      read STATE
   done

while [ $VIRTUAL_ROUTER_ID -lt "0" ] || [ $VIRTUAL_ROUTER_ID -gt "255" ]
   do
      echo -e "\e[1;33m### Please enter the VIRTUAL_ROUTER_ID of this Keepalived service (0-255) ?\e[0m"
      read VIRTUAL_ROUTER_ID
   done

while [ ! $PASSWORD ] || [ ${#PASSWORD} -gt 8 ]
   do
      echo -e "\e[1;33m### Please enter the Auth PASSWORD of this Keepalived service (Max 8 chars) ?\e[0m"
      read PASSWORD
   done

while [ ! $DISK_PATH ]
   do
      echo -e "\e[1;33m### Please enter the SYSLOG path for disk space check ?\e[0m"
      read DISK_PATH
   done

while [ ! $PRIORITY ]
   do
      if [ $STATE == "MASTER" ] ; then
         PRIORITY=101
      else
         PRIORITY=90
      fi
   done

DISTRO=$(awk '/^ID=/' /etc/*-release | awk -F'=' '{ print tolower($2) }' | sed -e 's/^"//' -e 's/"$//')
echo -e "\e[1;32m### Linux DISTRO is ==> " $DISTRO " ###\e[0m"

echo "### Checking if Keepalived installed..."
if [ $DISTRO == "centos" ] || [ $DISTRO ==  "rhel" ] || [ $DISTRO ==  "ol" ]; then
   yum list installed | grep keepalived || yum install keepalived -y
elif [ $DISTRO == "ubuntu" ]; then
   apt list --installed | grep keepalived || apt-get -y install keepalived
fi

if [ -f /etc/keepalived/keepalived.conf ]; then
   cp /etc/keepalived/keepalived.conf /etc/keepalived/keepalived.conf_$(date "+%Y%m%d%H%M%S")
fi

echo "### Creating configuration file ..."
cat <<EOT > /etc/keepalived/keepalived.conf
#global_defs {
#   notification_email {
#        sysadmin@mydomain.com
#   }
#   notification_email_from lb1@mydomain.com
#   smtp_server localhost
#   smtp_connect_timeout 30
#}

global_defs {
   script_user keepalived_script
   enable_script_security
}

vrrp_script chk_splunk {
   script "/usr/sbin/pidof splunkd"
   interval 2
}

vrrp_script chk_rsyslog {
   script "/usr/sbin/pidof rsyslogd"
   interval 2
}

vrrp_script chk_diskspace {
   script "/usr/libexec/keepalived/chk_diskspace.sh"
   interval 10
}

vrrp_instance VI_1 {
   state $STATE
   interface $INTERFACE
   virtual_router_id $VIRTUAL_ROUTER_ID
   priority $PRIORITY
   advert_int 1
   authentication {
         auth_type PASS
         auth_pass $PASSWORD
   }
   track_script {
         chk_splunk
         chk_rsyslog
         chk_diskspace
   }
   virtual_ipaddress {
         $VIRTUAL_IP
   }
}

EOT

if [ $LB ]; then
   cat <<EOT >> /etc/keepalived/keepalived.conf
virtual_server $VIRTUAL_IP 514 {
   delay_loop 10
   lb_algo rr
   lb_kind DR
   #persistence_timeout 5
   protocol TCP
EOT

   i=0
   IFS=,
   for LB_HOST in $LB; do

      cat <<EOT >> /etc/keepalived/keepalived.conf
   real_server $LB_HOST 514 {
       TCP_CHECK {
       }
   }
EOT
   done
   cat <<EOT >> /etc/keepalived/keepalived.conf
}
EOT

   cat <<EOT >> /etc/keepalived/keepalived.conf
virtual_server $VIRTUAL_IP 514 {
   delay_loop 10
   lb_algo rr
   lb_kind DR
   protocol UDP
   ops
EOT

   i=0
   for LB_HOST in $LB; do

      cat <<EOT >> /etc/keepalived/keepalived.conf
   real_server $LB_HOST 514 {
       TCP_CHECK {
       }
   }
EOT
   done
   IFS=$Field_Separator

   cat <<EOT >> /etc/keepalived/keepalived.conf
}
EOT

   cat <<EOT > /etc/sysconfig/network-scripts/ifcfg-lo:0
DEVICE=lo:0
IPADDR=$VIRTUAL_IP
NETMASK=255.255.255.255
ONBOOT=yes
NAME=loopback
EOT

   cat <<EOT > /etc/sysctl.d/splunk-lb-sysctl.conf
net.ipv4.conf.$INTERFACE.arp_ignore = 1
net.ipv4.conf.$INTERFACE.arp_announce = 2
# Enables packet forwarding
net.ipv4.ip_forward = 1
EOT

   sysctl -p
   ifup lo

fi

cat  <<EOT > /usr/libexec/keepalived/chk_diskspace.sh
#!/bin/bash
/usr/bin/df -Ph $DISK_PATH | /usr/bin/grep -v 'Use%' | /usr/bin/sed 's/%//g' | /usr/bin/awk '\$5 > 95 {err = 1; exit;}  END {exit err}'
EOT

if id -u keepalived_script >/dev/null 2>&1; then
   echo -e "\e[1;32m### keepalived_script user already exists###\e[0m"
else
   echo "### Creating keepalived_script user ###"
   useradd -M keepalived_script
fi

chmod +x /usr/libexec/keepalived/chk_diskspace.sh
chown keepalived_script /usr/libexec/keepalived/chk_diskspace.sh

echo "### Checking firewalld service..."
if [ $DISTRO == "centos" ] || [ $DISTRO ==  "rhel" ] || [ $DISTRO ==  "ol" ]; then
   if [ "$(yum list installed | grep firewalld)" ]; then
      if systemctl is-active --quiet firewalld; then
         if [ ! "$(firewall-cmd --list-rich-rules | grep 'rule protocol value=\"vrrp\" accept')" ]; then
             echo "### Adding VRRP rule..."
             firewall-cmd --add-rich-rule='rule protocol value="vrrp" accept' --permanent
             firewall-cmd --reload
          else
              echo "### VRRP rule exists..."
          fi
      fi
   fi
fi

echo "### Checking SELINUX setting..."
if grep "SELINUX=enforcing" /etc/selinux/config; then
   echo -e "\e[1;32m### SELinux is enforcing, changing to permissive...\e[0m"
   sed -i 's/^SELINUX=enforcing/SELINUX=permissive/g' /etc/selinux/config
   setenforce permissive
else
   echo "### SELinux is not enforcing..."
fi

echo "### Starting keepalived service..."
systemctl restart keepalived
echo "### Enabling keepalived service..."
systemctl enable keepalived

echo "### Waiting for the service to start for 15 seconds..."
sleep 15
if systemctl is-active --quiet keepalived; then
   echo -e "\e[1;32m### SUCCESS... Keepalived service started on this host as $STATE state\e[0m"
if [[ $STATE == "MASTER" ]]; then
   echo "Checking VIP address..."
   wait_counter=0
   while ! ip a s dev $INTERFACE | grep $VIRTUAL_IP
      do
         ((wait_counter++))
         echo "### Waiting for VIP address... $wait_counter sec "
         sleep 1
         if (test $wait_counter -gt 60); then
            echo "#############################################################################################################"
            echo -e "\e[1;31m### FAILED. Keepalived service couldn't get $VIRTUAL_IP, please check the parameters you set and try again...\e[0m"
            echo "#############################################################################################################"
            break
         fi
      done
   if [[ $wait_counter -lt "60" ]] && [[ $STATE == "MASTER" ]]; then
      echo -e "\e[1;32m### SUCCESS... Keepalived MASTER has $VIRTUAL_IP on this host...\e[0m"
   fi
fi
else
   echo -e "\e[1;31m### FAILED... Keepalived service couldn't start on this host as $STATE state\e[0m"
fi

echo "### Last 50 lines of log files of Keepalived..."

tail -n 50 /var/log/messages | grep Keepalived




