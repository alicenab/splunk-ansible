#!/bin/bash

 echo ''
 echo '##############################################'
 echo '#                                            #'
 echo '# Welcome to the Splunk Uninstaller          #'
 echo '# for CentOS/Ubuntu                          #'
 echo '# Last updated 08/04/2021.                   #'
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
Splunk Indexer
./uninstallSplunk.sh -p /data

#####################################################################################"
   exit 0
fi

############################# Start of Functions #############################

remove_firewall_rule () {
	echo "### Checking firewalld service $1 ..."
	if [ $DISTRO == "centos" ] || [ $DISTRO ==  "rhel" ] || [ $DISTRO ==  "ol" ]; then
		if [ "$(yum list installed | grep firewalld)" ]; then
			if systemctl is-active --quiet firewalld; then
				if [ "$(firewall-cmd --list-all | grep $1)" ]; then
					echo "### Removing $1 rule..."
					firewall-cmd --remove-port=$1 --permanent
					firewall-cmd --reload
				fi
			else
				echo "### firewalld installed but the service not active..."
			fi
		else
			echo "### firewalld not installed.."
		fi
	fi
}

############################# End of Functions #############################


while [ ! $INSTALL_PATH ]
   do
      echo -e "\e[1;33m### Please enter the Installation path for Splunk ?\e[0m"
      read INSTALL_PATH
   done


DISTRO=$(awk '/^ID=/' /etc/*-release | awk -F'=' '{ print tolower($2) }' | sed -e 's/^"//' -e 's/"$//')

if [ $DISTRO == "centos" ] || [ $DISTRO ==  "rhel" ] || [ $DISTRO ==  "ubuntu" ] || [ $DISTRO ==  "ol" ]; then
	echo ''
	echo "### Linux DISTRO is ==> "$DISTRO" ###"
	echo ''
else
	echo ''
	echo "### Unknown Linux DISTRO " $DISTRO " , quitting..."
	exit
fi
echo ''

echo "### Stopping Splunk..."
$INSTALL_PATH/splunk/bin/splunk stop -f
$INSTALL_PATH/splunk/bin/splunk disable boot-start

if id -u splunk >/dev/null 2>&1; then
	echo "### Deleting splunk user..."
	userdel -r splunk
	rm -rf /home/splunk
fi

if [ -f /etc/systemd/system/disable-thp.service ]; then
	echo "### Removing THP service..."
	systemctl stop disable-thp
	systemctl disable disable-thp
	rm -f /etc/systemd/system/disable-thp.service
	systemctl daemon-reload
fi

if [ -f /etc/security/limits.d/splunk_limits.conf ]; then
	echo "### Removing splunk user limits settings..."
	rm -f /etc/security/limits.d/splunk_limits.conf
fi

if [ -f /etc/keepalived/keepalived.conf ]; then
	echo "### Removing keepalived..."
	userdel keepalived_script
	rm -f /var/spool/mail/keepalived_script
	rm -f /etc/keepalived/keepalived.conf*
	rm -f /usr/libexec/keepalived/chk_diskspace.sh
	rm -f /etc/sysconfig/network-scripts/ifcfg-lo:0
	rm -f /etc/sysctl.d/splunk-lb-sysctl.conf
	yum remove keepalived -y
	firewall-cmd --remove-rich-rule='rule protocol value="vrrp" accept' --permanent
	firewall-cmd --reload
fi

if [ -f /etc/rsyslog.d/splunk*.conf ]; then
	echo "### Removing rsyslog conf..."
	rm -f /etc/rsyslog.d/splunk*.conf
	RSYSLOGVER=$(rsyslogd -v | grep 8.24.0)
	if [ ! "$RSYSLOGVER" ]; then
		rm -f /etc/yum.repos.d/rsyslog.repo
		yum downgrade rsyslog -y
	fi 	
	rm -rf $INSTALL_PATH/log
fi

if [ -f /etc/cron.d/splunk_hf ]; then
	echo "### Removing crontab conf..."
	rm -f /etc/cron.d/splunk_hf
fi

if [ $DISTRO == "centos" ] || [ $DISTRO ==  "rhel" ] || [ $DISTRO ==  "ol" ]; then
	tuned-adm auto_profile 
	echo "### Server profile changed to default auto_profile tuning. ###"
	echo ''
	echo "Removing firewalld rules"
	remove_firewall_rule "8089/tcp"
	remove_firewall_rule "9997/tcp"
	remove_firewall_rule "8000/tcp"
	remove_firewall_rule "8080/tcp"
	remove_firewall_rule "8191/tcp"
	remove_firewall_rule "514/tcp"
	remove_firewall_rule "514/udp"
fi

echo "### Deleting splunk folder..."
rm -rf $INSTALL_PATH/splunk

echo "### Deleting log files ..."
rm -f /tmp/installSplunk*
rm -f /tmp/SPLUNK_ROLE_FILE


