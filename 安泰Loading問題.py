#安泰Loading問題

#z_ossec_to_avt.conf 
from syslog import syslog


template(name="avtFormat" type="string"  string="%msg:R,ERE,0,DFLT:AV.*--end%\n")

if $fromhost-ip == ["192.168.144.196"] and $msg contains "AV - Alert")        #將Ossec log 來源IP塞入，ossec log才會落地
then{
    action(type="omfile" template="avtFormat" File="/var/ossec/logs/alerts/alerts.log.test")
}

#$template avtFormat,"%msg:R,ERE,0,DFLT:AV.*--end%\n"
#:msg,contains,"AV - Alert -" /var/ossec/logs/alerts/alerts.log; avtFormat



#forward_ossec2lm.conf 
#把local7拿掉
module(load="imfile")

template(name="lm_ossec_msg" type="string" string="%msg:::sp-if-no-1st-sp%%msg:::drop-last-lf%\n")

input(
    type="imfile"
    File="/var/ossec/logs/alerts/alerts.log"
    statefile="/var/spool/rsyslog/ossec"
    #Facility="local7"      
    #Tag="ossec:"
    ruleset="ossec_forward_msg"
)
#if $syslogtag == "ossec:" then {     
#   action(type="omfwd" Target="192.168.44.166" Port="10514" Protocol="udp" template="lm_ossec_msg")
#}


ruleset(name="ossec_forward_msg"){
    action(type="omfwd" Target="192.168.144.106" Port="10514" Protocol="udp" template="lm_ossec_msg")
}
