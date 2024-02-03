#!/bin/bash
> >(tee -ia installSplunkCluster_$(date "+%Y%m%d%H%M%S").log)
exec 2> >(tee -ia installSplunkCluster_$(date "+%Y%m%d%H%M%S").log >&2)

echo
echo '##############################################'
echo '#                                            #'
echo '# Welcome to the Splunk Cluster-installer    #'
echo '# for Linux.                                 #'
echo '# Last updated 10/05/2022.                   #'
echo '#                                            #'
echo '##############################################'

CM=cm
IDX=idx
DS=ds
DP=
SH=sh
HF=hf

ORG=cyber
VERSION=8.2.7
INSTALL_PATH=/data
REP_FACTOR=2
SEARCH_FACTOR=2
IDX_PASS4SYMMKEY=
SHC_PASS4SYMMKEY=
IDXDISCOVERY_PASS4SYMMKEY=
ADMIN_PASSWORD=cadmin123
HF_VIP=192.168.189.65
HF_LB=1
HOT_VOLUME_PATH=$INSTALL_PATH/splunk/var/lib/splunk
COLD_VOLUME_PATH=$INSTALL_PATH/splunk/var/lib/splunk
#MASTER_URI=https://10.13.55.105:8089
#DS_URI=https://10.13.55.106:8089
#DP_URI=https://10.13.55.107:8089

# Please update current Wget download link which you can get from https://www.splunk.com/download.
INSTALL_URL_V8_1_4='splunk-8.1.4-17f862b42a7c-Linux-x86_64.tgz'
INSTALL_URL_V8_1_5='splunk-8.1.5-9c0c082e4596-Linux-x86_64.tgz'
INSTALL_URL_V8_1_6='splunk-8.1.6-c1a0dd183ee5-Linux-x86_64.tgz'
INSTALL_URL_V8_1_8='splunk-8.1.8-39da583cc695-Linux-x86_64.tgz'
INSTALL_URL_V8_1_9='splunk-8.1.9-a16db3287b56-Linux-x86_64.tgz'
INSTALL_URL_V8_2_7='splunk-8.2.7-2e1fca123028-Linux-x86_64.tgz'

# Please update INSTALL_URL MD% hash values.
INSTALL_URL_V8_1_4_MD5=0d9fa82f82ac5cdac5cb30fe4ebb8cd6
INSTALL_URL_V8_1_5_MD5=5426ce57ebe9f102ece0d7c1fd09a916
INSTALL_URL_V8_1_6_MD5=861b78f25c84efe82a6ecdaa257617cb
INSTALL_URL_V8_1_8_MD5=ea2f65abc107b061efbd54507422fae0
INSTALL_URL_V8_1_9_MD5=071bca7d9138ee00ca8592886a267130
INSTALL_URL_V8_2_7_MD5=99dd11823d2a00e9eb84b6e1f385a674

INSTALL_URL=INSTALL_URL_V$(echo $VERSION | sed 's/\./_/g')
INSTALL_FILE=$(echo ${!INSTALL_URL})
INSTALL_URL_MD5=$(echo $INSTALL_URL)_MD5

INSTALL_URL='https://download.splunk.com/products/splunk/releases/'$(echo $VERSION)/linux/$(echo ${!INSTALL_URL})
INSTALL_URL_MD5=$(echo ${!INSTALL_URL_MD5})

while [ ! $INSTALL_URL ]; do
    echo -n "unknown version"
    exit -1
done

echo "INSTALL_URL= " $INSTALL_URL
echo "INSTALL_FILE_MD5= " $INSTALL_URL_MD5
echo "INSTALL_FILE= " $INSTALL_FILE

SCRIPT_PATH=$(pwd)

cd /tmp
if [ ! -f /tmp/$INSTALL_FILE ] || [ ! $INSTALL_URL_MD5 == $(md5sum /tmp/$INSTALL_FILE | awk '{print $1}') ]; then
    echo ''
    echo '### Splunk installation file not found or checksum failed, will be downloaded. ###'
    echo ''
    if [ -x "$(which curl)" ]; then
        echo "### Downloading Splunk installation tgz file using curl ###"
        curl -o $INSTALL_FILE -fL $INSTALL_URL
        #curl -o $INSTALL_FILE -fL --progress-bar $INSTALL_URL
    elif [ -x "$(which wget)" ]; then
        echo "### Downloading Splunk installation tgz file using wget ###"
        wget -O $INSTALL_FILE $INSTALL_URL
    else
        echo '### Could not find curl or wget ###'
        echo '### Trying to install wget ###'
        if [ $DISTRO == "centos" ] || [ $DISTRO == "rhel" ] || [ $DISTRO == "ol" ]; then
            yum install wget -y
        elif [ $DISTRO == "ubuntu" ]; then
            apt-get -y install wget
        fi
        if [ -x "$(which wget)" ]; then
            echo "### Downloading Splunk installation tgz file using wget ###"
            wget -O $INSTALL_FILE $INSTALL_URL
        fi
    fi

    echo ''
    if [ ! -f /tmp/$INSTALL_FILE ] || [ ! $INSTALL_URL_MD5 == $(md5sum /tmp/$INSTALL_FILE | awk '{print $1}') ]; then
        echo "### Splunk installation file download error, quitting...###"
        exit
    else
        echo "### Splunk installation file Downloaded. ###"
    fi
else
    echo "### Splunk installation file already exists. ###"
fi

[ ! $MASTER_URI ] && MASTER_URI=https://$(clush -g $CM -b ip route show | grep src | awk '{print $11,$9}' | sort | head -n 1 | awk '{print $2}'):8089
[ ! $DS_URI ] && DS_URI=https://$(clush -g $DS -b ip route show | grep src | awk '{print $11,$9}' | sort | head -n 1 | awk '{print $2}'):8089
[ ! $DP_URI ] && DP_URI=https://$(clush -g $DP -b ip route show | grep src | awk '{print $11,$9}' | sort | head -n 1 | awk '{print $2}'):8089

[ ! $ADMIN_PASSWORD ] && ADMIN_PASSWORD=$(openssl rand -base64 12)
[ ! $IDX_PASS4SYMMKEY ] && IDX_PASS4SYMMKEY=$(openssl rand -base64 12)
[ ! $SHC_PASS4SYMMKEY ] && SHC_PASS4SYMMKEY=$(openssl rand -base64 12)
[ ! $IDXDISCOVERY_PASS4SYMMKEY ] && IDXDISCOVERY_PASS4SYMMKEY=$(openssl rand -base64 12)

SPLUNK_HOSTS=""

[ $CM ] && SPLUNK_HOSTS+=" $CM"
[ $IDX ] && SPLUNK_HOSTS+=" $IDX"
[ $DS ] && SPLUNK_HOSTS+=" $DS"
[ $SH ] && SPLUNK_HOSTS+=" $SH"
[ $DP ] && SPLUNK_HOSTS+=" $DP"
[ $HF ] && SPLUNK_HOSTS+=" $HF"

for SPLUNK_HOST in $SPLUNK_HOSTS; do
    SPLUNK_ROLE=${SPLUNK_HOST^^}
    echo "### Copying script to hosts in $SPLUNK_HOST group ..."
    clush -g $SPLUNK_HOST -c $SCRIPT_PATH/installSplunk.sh --dest /tmp
    echo "### Copying installation file to hosts in $SPLUNK_HOST group ..."
    clush -g $SPLUNK_HOST -c /tmp/$INSTALL_FILE
    echo "### Setting role for hosts in $SPLUNK_HOST group ..."
    echo $SPLUNK_ROLE >$SCRIPT_PATH/SPLUNK_ROLE_FILE
    clush -g $SPLUNK_HOST -c $SCRIPT_PATH/SPLUNK_ROLE_FILE --dest /tmp
done

rm -f $SCRIPT_PATH/SPLUNK_ROLE_FILE

if [ $DS ]; then
    HF_HOSTNAMES=$(clush -g $HF hostname | awk '{print $2}' | tr "\n" " ")
    HF_HOST_WHITELIST+=[serverClass:All_HeavyForwarders]$'\n'
    i=0
    for HF_HOST in $HF_HOSTNAMES; do
        HF_HOST_WHITELIST+=whitelist.$i$'='$HF_HOST$'\n'
        i=$((i + 1))
    done
    #echo "$HF_HOST_WHITELIST"
fi

echo "### Starting installation for all hosts ..."
clush -a -b bash "/tmp/installSplunk.sh -r FILE -o $ORG -v $VERSION -p $INSTALL_PATH -a $ADMIN_PASSWORD -e $REP_FACTOR -s $SEARCH_FACTOR -i $IDX_PASS4SYMMKEY -k $SHC_PASS4SYMMKEY -c $IDXDISCOVERY_PASS4SYMMKEY -m $MASTER_URI -d $DS_URI -b $DP_URI -w $HOT_VOLUME_PATH -u $COLD_VOLUME_PATH -x '$HF_HOST_WHITELIST'"

if [ $DP ]; then
    echo "### Preparing for Search Head Clustering setup..."
    SH_HOSTS_IP=$(clush -g $SH -b ip route show | grep src | awk '{print $11,$9}' | sort | awk '{print $2}' | tr "\n" " ")
    SH_HOSTS=$(nodeset -e @$SH)
    declare -a SH_URI
    i=0
    for SH_HOST_IP in $SH_HOSTS_IP; do
        SH_URI[i]=https://$SH_HOST_IP:8089
        SERVER_LIST+=${SH_URI[i]},
        MC_assets+=\"$SH_HOST_IP:8089\",,,,\"dmc_group_searchhead\",0,,,,,,,,$'\n'
        i=$((i + 1))
    done
    SH_CAPTAIN_URI=${SH_URI[0]}
    SERVER_LIST=${SERVER_LIST::-1}
    echo "### SH Captain is $SH_CAPTAIN_URI ..."
    echo "### SH SERVER_LIST = $SERVER_LIST ..."

    i=0
    for SH_HOST in $SH_HOSTS; do
        echo "### İnitializing sh-cluster on search head $SH_HOST ..."
        clush -w $SH_HOST -b $INSTALL_PATH/splunk/bin/splunk init shcluster-config -auth ${ORG}admin:$ADMIN_PASSWORD -mgmt_uri ${SH_URI[i]} -replication_port 8080 -replication_factor $SEARCH_FACTOR -conf_deploy_fetch_url $DP_URI -secret $SHC_PASS4SYMMKEY -shcluster_label ${ORG}-SHCluster
        clush -w $SH_HOST -b firewall-cmd --permanent --add-port=8191/tcp
        clush -w $SH_HOST -b firewall-cmd --permanent --add-port=8080/tcp
        clush -w $SH_HOST -b firewall-cmd --reload
        if [[ $i -eq "0" ]]; then
            SH_CAPTAIN_HOST=$SH_HOST
        fi
        i=$((i + 1))
    done

    echo "### Restarting Search Heads ..."
    clush -g $SH -b $INSTALL_PATH/splunk/bin/splunk restart

    echo "### Boostrapping captain for SH SERVER_LIST = $SERVER_LIST ..."
    clush -w $SH_CAPTAIN_HOST -b $INSTALL_PATH/splunk/bin/splunk bootstrap shcluster-captain -servers_list $SERVER_LIST -auth ${ORG}admin:$ADMIN_PASSWORD

    while ! clush -w $SH_CAPTAIN_HOST -b $INSTALL_PATH/splunk/bin/splunk show shcluster-status | grep "dynamic_captain : 1"; do
        echo "### Waiting for  the SHC Captain election..."
        sleep 5
    done

    echo "### SHC Captain elected..."
    clush -w $SH_CAPTAIN_HOST -b $INSTALL_PATH/splunk/bin/splunk show shcluster-status

    while ! clush -w $SH_CAPTAIN_HOST -b $INSTALL_PATH/splunk/bin/splunk show shcluster-status | grep "service_ready_flag : 1"; do
        echo "### Waiting for SHC service becomes ready"
        sleep 5
    done

    echo "### Applying shcluster-bundle to SHC ..."
    clush -g $DP -b $INSTALL_PATH/splunk/bin/splunk apply shcluster-bundle -target $SH_CAPTAIN_URI -auth ${ORG}admin:$ADMIN_PASSWORD --answer-yes

   echo "### Setting up Monitoring Console ..."

    echo "### Adding CM as search peer ..."
    clush -g $DP -b $INSTALL_PATH/splunk/bin/splunk add search-server $MASTER_URI -auth ${ORG}admin:$ADMIN_PASSWORD -remoteUsername ${ORG}admin -remotePassword $ADMIN_PASSWORD
    echo "### Adding DS as search peer ..."
    clush -g $DP -b $INSTALL_PATH/splunk/bin/splunk add search-server $DS_URI -auth ${ORG}admin:$ADMIN_PASSWORD -remoteUsername ${ORG}admin -remotePassword $ADMIN_PASSWORD
    echo "### Adding Search Heads as search peers ..."
    for SH_HOST_IP in $SH_HOSTS_IP; do
        clush -g $DP -b $INSTALL_PATH/splunk/bin/splunk add search-server https://$SH_HOST_IP:8089 -auth ${ORG}admin:$ADMIN_PASSWORD -remoteUsername ${ORG}admin -remotePassword $ADMIN_PASSWORD
        MC_assets+=\"$SH_HOST_IP:8089\",,,,\"dmc_group_search_head\",0,,,,,,,,$'\n'
        MC_assets+=\"$SH_HOST_IP:8089\",,,,\"dmc_searchheadclustergroup_$ORG-SHCluster\",1,,,,,,,,$'\n'
        MC_assets+=\"$SH_HOST_IP:8089\",,,,\"dmc_indexerclustergroup_$ORG-IDXCluster\",2,,,,,,,,$'\n'
        MC_CONFIGURED_PEERS+=$SH_HOST_IP:8089,
        sleep 5
    done

    echo "### Preparing for Indexers Monitoring Console settings..."
    IDX_HOSTS_IP=$(clush -g $IDX -b ip route show | grep src | awk '{print $11,$9}' | sort | awk '{print $2}' | tr "\n" " ")
    for IDX_HOST_IP in $IDX_HOSTS_IP; do
        MC_assets+=\"$IDX_HOST_IP:8089\",,,,\"dmc_group_indexer\",0,,,,,,,,$'\n'
        MC_CONFIGURED_PEERS+=$IDX_HOST_IP:8089,
    done

    MC_CONFIGURED_PEERS+=$(echo $MASTER_URI | sed 's/https:\/\///g'),
    MC_CONFIGURED_PEERS+=$(echo $DS_URI | sed 's/https:\/\///g')

    cat <<EOT >$SCRIPT_PATH/assets.csv
peerURI,serverName,host,machine,"search_group","_mkv_child","_timediff","__mv_peerURI","__mv_serverName","__mv_host","__mv_machine","__mv_search_group","__mv__mkv_child","__mv__timediff"
localhost,,,,"dmc_group_shc_deployer",0,,,,,,,
localhost,,,,"dmc_searchheadclustergroup_$ORG-SHCluster",1,,,,,,,
"$(echo $MASTER_URI | sed 's/https:\/\///g')",,,,"dmc_group_cluster_master",0,,,,,,,,
"$(echo $MASTER_URI | sed 's/https:\/\///g')",,,,"dmc_group_license_master",1,,,,,,,,
"$(echo $DS_URI | sed 's/https:\/\///g')",,,,"dmc_group_deployment_server",0,,,,,,,,
$MC_assets
EOT

    cat <<EOT >$SCRIPT_PATH/splunk_monitoring_console_assets.conf
[settings]
disabled = 0
configuredPeers = $MC_CONFIGURED_PEERS

EOT

    cat <<EOT >$SCRIPT_PATH/savedsearches.conf
[DMC Asset - Build Standalone Asset Table]
disabled = 1

EOT

    cat <<EOT >$SCRIPT_PATH/app.conf
[install]
is_configured = 1

EOT

    cat <<EOT >$SCRIPT_PATH/distsearch.conf
[distributedSearch]
servers = $MC_CONFIGURED_SH_PEERS $MC_CONFIGURED_IDX_PEERS $(echo $MASTER_URI | sed 's/https:\/\///g'), $(echo $DS_URI | sed 's/https:\/\///g')

[distributedSearch:dmc_group_cluster_master]
servers = $(echo $MASTER_URI | sed 's/https:\/\///g')

[distributedSearch:dmc_group_deployment_server]
servers = $(echo $DS_URI | sed 's/https:\/\///g')

[distributedSearch:dmc_group_indexer]
default = true
servers = $MC_CONFIGURED_IDX_PEERS

[distributedSearch:dmc_group_license_master]
servers = $(echo $MASTER_URI | sed 's/https:\/\///g')

[distributedSearch:dmc_group_shc_deployer]
servers = localhost:localhost

[distributedSearch:dmc_group_search_head]
servers = $MC_CONFIGURED_SH_PEERS

[distributedSearch:dmc_group_kv_store]
servers = $MC_CONFIGURED_SH_PEERS

[distributedSearch:dmc_indexerclustergroup_test-IDXCluster]
servers = $MC_CONFIGURED_SH_PEERS $MC_CONFIGURED_IDX_PEERS $(echo $MASTER_URI | sed 's/https:\/\///g')

[distributedSearch:dmc_searchheadclustergroup_test-SHCluster]
servers = localhost:localhost,$MC_CONFIGURED_SH_PEERS

EOT

    clush -g $DP -b mkdir $INSTALL_PATH/splunk/etc/apps/splunk_monitoring_console/local -p
    clush -g $DP -b -c $SCRIPT_PATH/assets.csv --dest $INSTALL_PATH/splunk/etc/apps/splunk_monitoring_console/lookups/assets.csv
    clush -g $DP -b -c $SCRIPT_PATH/splunk_monitoring_console_assets.conf --dest $INSTALL_PATH/splunk/etc/apps/splunk_monitoring_console/local/splunk_monitoring_console_assets.conf
    clush -g $DP -b -c $SCRIPT_PATH/savedsearches.conf --dest $INSTALL_PATH/splunk/etc/apps/splunk_monitoring_console/local/savedsearches.conf
    clush -g $DP -b -c $SCRIPT_PATH/distsearch.conf --dest $INSTALL_PATH/splunk/etc/apps/splunk_monitoring_console/local/distsearch.conf
    clush -g $DP -b -c $SCRIPT_PATH/app.conf --dest $INSTALL_PATH/splunk/etc/apps/splunk_monitoring_console/local/app.conf

    rm -f $SCRIPT_PATH/assets.csv 
    rm -f $SCRIPT_PATH/splunk_monitoring_console_assets.conf 
    rm -f $SCRIPT_PATH/savedsearches.conf 
    rm -f $SCRIPT_PATH/distsearch.conf 
    rm -f $SCRIPT_PATH/app.conf 

    clush -g $DP -b chown -R splunk: $INSTALL_PATH

    echo "### Restarting Deployer ..."
    clush -g $DP -b $INSTALL_PATH/splunk/bin/splunk restart

    echo "### Done setting up Monitoring Console ..."

fi

echo "### Setting up syslog servers on HF hosts hosts ..."
if [ $HF ]; then
    clush -g $HF -c $SCRIPT_PATH/installKeepalived.sh --dest /tmp
    [ $HF_LB ] && HF_IPLIST=$(clush -g $HF -b ip route show | grep src | awk '{print $11,$9}' | sort | awk '{print $2}' | tr "\n" "," | sed 's/.$//')
    HF_HOSTS=$(nodeset -e @$HF)
    HF_STATE=MASTER
    HF_PRIORITY=101
    VRRP_PASSWORD=$(openssl rand -base64 12 | cut -c1-8)
    clush -g $HF curl -o /etc/yum.repos.d/rsyslog.repo http://rpms.adiscon.com/v8-stable/rsyslog-rhel.repo
    clush -g $HF yum install rsyslog -y
    clush -g $HF mkdir $INSTALL_PATH/log
    clush -g $HF chcon system_u:object_r:var_log_t:s0 $INSTALL_PATH/log

    cat <<EOT >$SCRIPT_PATH/splunk_rsyslog.conf
#global(
#DefaultNetstreamDriverCAFile="/etc/rsyslog.d/tls/splunk.pem"
#DefaultNetstreamDriverCertFile="/etc/rsyslog.d/tls/splunk.pem"
#DefaultNetstreamDriverKeyFile="/etc/rsyslog.d/tls/splunk.key"
#)
template (name="splunk_file_template" type="string" string="/data/log/splunk/syslog/%FROMHOST-IP%/%\$MYHOSTNAME%-%\$YEAR%-%\$MONTH%-%\$DAY%-%\$HOUR%.log")
template (name="splunk_syslog_template" type="string" string="%syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")
template (name="splunk_syslog_template_with_ts" type="string" string="%timestamp% %syslogtag%%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")

ruleset(name="splunk"
        queue.workerThreads="4"
       ){

if (fromhost-ip == '1.2.3.4' or fromhost-ip == '1.2.3.5') then {
    action(type="omfile" fileOwner="root" fileGroup="root" DirCreateMode="0755" FileCreateMode="0644" dynaFile="splunk_file_template" dynaFileCacheSize="200" ioBufferSize="64k" template="splunk_syslog_template_with_ts")}

else {
action(type="omfile" fileOwner="root" fileGroup="root" DirCreateMode="0755" FileCreateMode="0644" dynaFile="splunk_file_template" dynaFileCacheSize="200" ioBufferSize="64k" template="splunk_syslog_template")}

}

module(load="imudp" threads="2" timeRequery="8" batchSize="128")
module(load="imptcp" threads="3")
#module(load="imtcp" StreamDriver.Name="gtls" StreamDriver.Mode="1" StreamDriver.Authmode="anon")

input(type="imudp" port="514" ruleset="splunk")
input(type="imptcp" port="514" SupportOctetCountedFraming="off" ruleset="splunk")
#input(type="imtcp" port="10514" ruleset="splunk")

#openssl req -newkey rsa:2048 -new -nodes -x509 -days 3650 -keyout /etc/rsyslog.d/tls/splunk.key -out /etc/rsyslog.d/tls/splunk.pem
#openssl s_client -connect localhost:10514 #testing

\$Umask 0022
\$PreserveFQDN on
\$MaxMessageSize 64k
\$MainMsgQueueSize 100000
\$DynaFileCacheSize 200
\$OMFileIOBufferSize 64k
\$RulesetCreateMainQueue on
\$RuleSet RSYSLOG_DefaultRuleset
\$EscapeControlCharactersOnReceive off
EOT
    clush -g $HF -c $SCRIPT_PATH/splunk_rsyslog.conf --dest /etc/rsyslog.d
    clush -g $HF systemctl restart rsyslog
    cat <<EOT >$SCRIPT_PATH/splunk_hf
# crontab setting for removing log files
0 * * * * root /usr/bin/find /data/log/splunk/syslog/. -maxdepth 2 -name "*.log" -type f -mmin +1440 -delete
5 * * * * root /usr/bin/find /data/log/splunk/syslog/. -type d -empty -delete
EOT
    clush -g $HF -c $SCRIPT_PATH/splunk_hf --dest /etc/cron.d
    for HF_HOST in $HF_HOSTS; do
        HF_INTERFACE=$(clush -w $HF_HOST -b ip route show | grep src | awk '{print $3}')
        if [ $HF_IPLIST ]; then
            clush -w $HF_HOST bash /tmp/installKeepalived.sh -v $HF_VIP -i $HF_INTERFACE -l $HF_IPLIST -s $HF_STATE -p $VRRP_PASSWORD -r 51 -P $HF_PRIORITY -d $INSTALL_PATH 
        else
            clush -w $HF_HOST bash /tmp/installKeepalived.sh -v $HF_VIP -i $HF_INTERFACE -s $HF_STATE -p $VRRP_PASSWORD -r 51 -P $HF_PRIORITY -d $INSTALL_PATH 
        fi
        HF_STATE=BACKUP
        HF_PRIORITY=$((HF_PRIORITY - 10))
    done 
fi

echo ''
echo "### Splunk Cluster Installation Completed..."
echo ''

[ ! $SERVER_LIST ] && SERVER_LIST=https://$(clush -g $SH -b ip route show | grep src | awk '{print $11,$9}' | sort | head -n 1 | awk '{print $2}'):8089

[ $SH ] &&     echo "Search Heads URLs                --> " $(echo $SERVER_LIST | sed s/8089/8000/g)
[ $CM ] &&     echo "ClusterMaster URL                --> " $(echo $MASTER_URI | sed s/8089/8000/g)
[ $DS ] &&     echo "Deployment Server URL            --> " $(echo $DS_URI | sed s/8089/8000/g)
[ $DP ] &&     echo "Deployer URL                     --> " $(echo $DP_URI | sed s/8089/8000/g)
[ $HF ] &&     echo "Heavy Forwarders                 --> " $(clush -g $HF -b ip route show | grep src | awk '{print $11,$9}' | sort | awk '{print $2}' | tr "\n" " ")
[ $HF_VIP ] && echo "Heavy Forwarders VIP address     --> " $HF_VIP 
[ $IDX ] &&    echo "Indexers                         --> " $(clush -g $IDX -b ip route show | grep src | awk '{print $11,$9}' | sort | awk '{print $2}' | tr "\n" " ")
               echo "Splunk Admin Username            --> " ${ORG}admin
               echo "Splunk Admin Password            --> " $ADMIN_PASSWORD
               echo "Indexer Cluster PASS4SYMMKEY     --> " $IDX_PASS4SYMMKEY
[ $DP ] &&     echo "Search Head Cluster PASS4SYMMKEY --> " $SHC_PASS4SYMMKEY
               echo "Indexer Discovery PASS4SYMMKEY   --> " $IDXDISCOVERY_PASS4SYMMKEY
echo ''


