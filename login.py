from nssrc.com.citrix.netscaler.nitro.exception.nitro_exception import nitro_exception
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver import lbvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.service import service
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_service_binding import lbvserver_service_binding
from nssrc.com.citrix.netscaler.nitro.resource.stat.lb.lbvserver_stats import lbvserver_stats
from nssrc.com.citrix.netscaler.nitro.service.nitro_service import nitro_service
from nssrc.com.citrix.netscaler.nitro.service.options import options
from nssrc.com.citrix.netscaler.nitro.util.filtervalue import filtervalue
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver import lbvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_cachepolicy_binding import lbvserver_cachepolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_service_binding import lbvserver_service_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.appfw.appfwconfidfield import appfwconfidfield
from nssrc.com.citrix.netscaler.nitro.resource.config.appfw.appfwlearningdata import appfwlearningdata
from nssrc.com.citrix.netscaler.nitro.resource.config.appfw.appfwlearningdata_args import appfwlearningdata_args
from nssrc.com.citrix.netscaler.nitro.resource.config.appfw.appfwprofile import appfwprofile
from nssrc.com.citrix.netscaler.nitro.resource.config.audit.auditnslogaction import auditnslogaction
from nssrc.com.citrix.netscaler.nitro.resource.config.audit.auditsyslogparams import auditsyslogparams
from nssrc.com.citrix.netscaler.nitro.resource.config.authorization.authorizationpolicylabel_binding import authorizationpolicylabel_binding 
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.service import service
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.service_binding import service_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.servicegroup_servicegroupmember_binding import servicegroup_servicegroupmember_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.basic.service_lbmonitor_binding import service_lbmonitor_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.cache.cacheobject import cacheobject
from nssrc.com.citrix.netscaler.nitro.resource.config.cmp.cmppolicy_lbvserver_binding import cmppolicy_lbvserver_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.dns.dnsnsecrec import dnsnsecrec
from nssrc.com.citrix.netscaler.nitro.resource.config.dns.dnssuffix import dnssuffix
from nssrc.com.citrix.netscaler.nitro.resource.config.dns.dnsview_dnspolicy_binding import dnsview_dnspolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.dns.dnszone import dnszone
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbldnsentries import gslbldnsentries
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbparameter import gslbparameter
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbservice import gslbservice
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbservice_binding import gslbservice_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbsite import gslbsite
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbvserver import gslbvserver
from nssrc.com.citrix.netscaler.nitro.resource.config.gslb.gslbvserver_gslbservice_binding import gslbvserver_gslbservice_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.ha.hanode import hanode
from nssrc.com.citrix.netscaler.nitro.resource.config.lb.lbvserver_binding import lbvserver_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.network.Interface import Interface
from nssrc.com.citrix.netscaler.nitro.resource.config.network.channel import channel
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsacl import nsacl
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsip import nsip
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsip_args import nsip_args
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nslimitidentifier import nslimitidentifier
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nstcpbufparam import nstcpbufparam
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsversion import nsversion
from nssrc.com.citrix.netscaler.nitro.resource.config.ns.nsxmlnamespace import nsxmlnamespace
from nssrc.com.citrix.netscaler.nitro.resource.config.policy.policyexpression import policyexpression
from nssrc.com.citrix.netscaler.nitro.resource.config.policy.policyexpression_args import policyexpression_args
from nssrc.com.citrix.netscaler.nitro.resource.config.protocol.protocolhttpband import protocolhttpband
from nssrc.com.citrix.netscaler.nitro.resource.config.protocol.protocolhttpband_args import protocolhttpband_args
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmpgroup import snmpgroup
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmpmanager import snmpmanager
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmpoid import snmpoid
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmpoid_args import snmpoid_args
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmptrap import snmptrap
from nssrc.com.citrix.netscaler.nitro.resource.config.snmp.snmpuser import snmpuser
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslcertkey import sslcertkey
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslcipher_binding import sslcipher_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslfipskey import sslfipskey
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslpolicy_binding import sslpolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.ssl.sslpolicy_csvserver_binding import sslpolicy_csvserver_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.system.systemgroup_binding import systemgroup_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.transform.transformprofile_transformaction_binding import transformprofile_transformaction_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnglobal_authenticationldappolicy_binding import vpnglobal_authenticationldappolicy_binding
from nssrc.com.citrix.netscaler.nitro.resource.config.vpn.vpnglobal_vpnclientlessaccesspolicy_binding import vpnglobal_vpnclientlessaccesspolicy_binding


'''
ns_session = nitro_service("172.17.0.2","https")
ns_session.certvalidation = False
ns_session.hostnameverification = False
ns_session.login("nsroot","nsroot",3600)
'''
import json
import requests

token = None
def cpxlogin(ip="172.17.0.2",username="nsroot",password="nsroot"):
	global token
	url="http://"+ip+"/nitro/v1/config/login"
	headers = {'Content-type': 'application/vnd.com.citrix.netscaler.login+json'}
	content = {"login":{"username":username,"password":password}}
	request = requests.post(url,data=json.dumps(content),headers=headers)
	print(type(request))
	print(request.headers)
	print("\n\n")
	print(request.headers.get('Set-Cookie'))
	cookie = request.headers.get('Set-Cookie')
	print(type(cookie))
	var = cookie.split(' ')
	var = var[7].split('=')
	token = var[1][:-1]
	print(token)
	#print("logged in\n\n")
	token = 'NITRO_AUTH_TOKEN='+token
	return request.status_code



def cpxlogout(ip="172.17.0.2"):
	global token
	url="http://"+ip+"/nitro/v1/config/logout"
	headers = {'Content-type': 'application/json','Cookie':token}
	payload = {"logout":{}}
	request = requests.post(url,data=json.dumps(payload),headers=headers)
	token = None
	print("logout status code ",request.status_code)
	return request.status_code

'''
url = 'http://172.17.0.2/nitro/v1/config/nsfeature?action=enable'
headers = {'Content-type': 'application/json','Cookie':token}
payload={"nsfeature":{"feature":["LB","CS"]}}

#request = list(request.headers)
#print(request)
#print(request.headers.get('NITRO_AUTH_TOKEN'))
request = requests.post(url,data=json.dumps(payload),headers=headers)
print("mode set  ",request.status_code)
'''


login = cpxlogin("172.17.0.2","nsroot","nsroot")
if login == 200 or login == 201:
	print("login successful")
	logout = cpxlogout("172.17.0.2")
	if(logout==200 or logout == 201):
		print("logout successful")
else:
	print("login unsuccessful")
