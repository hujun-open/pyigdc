#!/usr/bin/env python


#-------------------------------------------------------------------------------
# Name:        A UPNP IGD Client, implements following services:
#               - WANIPConnection
#               - WANIPv6FirewallControl
# Desc:        Could be used as CLI client or a client lib. to use it as lib,
#              use class IGDClient
#              require python 2.6+, python3 is not supported
#
# Author:      Hu Jun
#
# Created:     10/26/2015
# Copyright:   (c) Hu Jun 2015
# Licence:     MIT
#-------------------------------------------------------------------------------

import socket
import argparse
import urllib2
from StringIO import StringIO
from httplib import HTTPResponse
from xml.dom import minidom
from urlparse import urlparse
import re
import json
import ctypes
import os

class sockaddr(ctypes.Structure):
    _fields_ = [("sa_family", ctypes.c_short),
                ("__pad1", ctypes.c_ushort),
                ("ipv4_addr", ctypes.c_byte * 4),
                ("ipv6_addr", ctypes.c_byte * 16),
                ("__pad2", ctypes.c_ulong)]

if hasattr(ctypes, 'windll'):
    WSAStringToAddressA = ctypes.windll.ws2_32.WSAStringToAddressA
    WSAAddressToStringA = ctypes.windll.ws2_32.WSAAddressToStringA
else:
    def not_windows():
        raise SystemError(
            "Invalid platform. ctypes.windll must be available."
        )
    WSAStringToAddressA = not_windows
    WSAAddressToStringA = not_windows


def inet_pton(address_family, ip_string):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = ctypes.c_int(ctypes.sizeof(addr))

    if WSAStringToAddressA(
            ip_string,
            address_family,
            None,
            ctypes.byref(addr),
            ctypes.byref(addr_size)
    ) != 0:
        raise socket.error(ctypes.FormatError())

    if address_family == socket.AF_INET:
        return ctypes.string_at(addr.ipv4_addr, 4)
    if address_family == socket.AF_INET6:
        return ctypes.string_at(addr.ipv6_addr, 16)

    raise socket.error('unknown address family')


def inet_ntop(address_family, packed_ip):
    addr = sockaddr()
    addr.sa_family = address_family
    addr_size = ctypes.c_int(ctypes.sizeof(addr))
    ip_string = ctypes.create_string_buffer(128)
    ip_string_size = ctypes.c_int(ctypes.sizeof(ip_string))

    if address_family == socket.AF_INET:
        if len(packed_ip) != ctypes.sizeof(addr.ipv4_addr):
            raise socket.error('packed IP wrong length for inet_ntoa')
        ctypes.memmove(addr.ipv4_addr, packed_ip, 4)
    elif address_family == socket.AF_INET6:
        if len(packed_ip) != ctypes.sizeof(addr.ipv6_addr):
            raise socket.error('packed IP wrong length for inet_ntoa')
        ctypes.memmove(addr.ipv6_addr, packed_ip, 16)
    else:
        raise socket.error('unknown address family')

    if WSAAddressToStringA(
            ctypes.byref(addr),
            addr_size,
            None,
            ip_string,
            ctypes.byref(ip_string_size)
    ) != 0:
        raise socket.error(ctypes.FormatError())

    return ip_string[:ip_string_size.value - 1]

# Adding our two functions to the socket library
if os.name == 'nt':
    socket.inet_pton = inet_pton
    socket.inet_ntop = inet_ntop


def str2bool(bstr):
    return bool(int(bstr))

def getProtoId(proto_name):
    if proto_name=="UDP":
        return 17
    if proto_name=="TCP":
        return 6
    if proto_name=="SCTP":
        return 132
    if proto_name=="ALL":
        return 65535
    if isinstance(proto_name,int):
        if proto_name>0 and proto_name<=65535:
            return proto_name
    return False



def isv6(addr):
    if addr.find(":")!=-1:
        return True
    else:
        if addr.count(".")>3:
            return True
        else:
            return False

def isLLA(addr):
    """return True if addr is IPv6 Link Local Address"""
    if isv6(addr)==False:
        return False
    if "%" in addr:
        addr=addr.split("%")[0]
    bina=socket.inet_pton(socket.AF_INET6,addr)
    if bina[0:8]=="\xfe\x80\x00\x00\x00\x00\x00\x00":
        return True
    else:
        return False




UPNPTYPEDICT={
"NewUptime":int,
"NewAutoDisconnectTime":int,
"NewIdleDisconnectTime":int,
"NewWarnDisconnectDelay":int,
"NewPortMappingNumberOfEntries":int,
"NewLeaseDuration":int,
"NewExternalPort":int,
"NewInternalPort":int,
"NewRSIPAvailable":str2bool,
"NewNATEnabled":str2bool,
"NewEnabled":str2bool,
"FirewallEnabled":str2bool,
"InboundPinholeAllowed":str2bool,
"OutboundPinholeTimeout":int,
"UniqueID":int,
"PinholePackets":int,
"IsWorking":str2bool,

}

class UPNPError(Exception):
    def __init__(self,hcode,ucode,udes):
        """
        hcode is the http error code
        ucode is the upnp error code
        udes is the upnp error description
        """
        self.http_code=hcode
        self.code=ucode
        self.description=udes
    def __str__(self):
        return "HTTP Error Code {hc}, UPnP Error Code {c}, {d}"\
            .format(hc=self.http_code,c=self.code, d=self.description)


class FakeSocket(StringIO):
    def makefile(self, *args, **kw):
        return self

def httpparse(fp):
    socket = FakeSocket(fp.read())
    response = HTTPResponse(socket)
    response.begin()
    return response

def parseErrMsg(err_resp):
    """
    parse UPnP error message, err_resp is the returned XML in http body
    reurn UPnP error code and error description
    """
    dom=minidom.parseString(err_resp)
    err_code=int(dom.getElementsByTagName('errorCode')[0].firstChild.nodeValue)
    err_desc=dom.getElementsByTagName('errorDescription')[0].firstChild.nodeValue
    return (err_code,err_desc)

def get1stTagText(xmls,tagname_list):
    """
    return 1st tag's value in the xmls
    """
    global UPNPTYPEDICT
    dom=minidom.parseString(xmls)
    r={}
    for tagn in tagname_list:
        try:
            txt_node = dom.getElementsByTagName(tagn)[0].firstChild
            if txt_node != None:
                if tagn in UPNPTYPEDICT:
                    r[tagn] = UPNPTYPEDICT[tagn](txt_node.nodeValue)
                else:
                    r[tagn] = txt_node.nodeValue
            else:
                r[tagn] = None
        except:
            print"xml parse err: {tag} not found".format(tag=tagn)
    return r


#sendSOAP is based on part of source code from miranda-upnp.




class IGDClient:
    """
    UPnP IGD v1 Client class, supports all actions
    """
    def __init__(self, intIP,ctrlURL=None,service="WANIPC",edebug=False,pprint=False):
        """
        - intIP is the source address of the request packet, which implies the source interface
        - ctrlURL is the the control URL of IGD server, client will do discovery if it is None
        """
        self.debug=edebug
        self.pprint=pprint
        self.intIP=intIP #the source addr of the client
        self.ctrlURL=ctrlURL
        if isv6(intIP):
            self.igdsvc="IP6FWCTL"
        else:
            self.igdsvc="WANIPC"
        if self.ctrlURL == None:
            self.discovery()



    def enableDebug(self,d=True):
        """
        enable debug output
        """
        self.debug=d

    def enablePPrint(self,p=True):
        """
        enable pretty print for XML output
        """
        self.pprint=p

    def discovery(self):
        """
        Find IGD device and its control URL via UPnP multicast discovery
        """
        if not isv6(self.intIP):
            up_disc='M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMX:2\r\nMAN:"ssdp:discover"\r\n\r\n'
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.bind((self.intIP,19110))
            sock.sendto(up_disc, ("239.255.255.250", 1900))
        else:
            if isLLA(self.intIP):
                dst_ip="ff02::c"
            else:
                dst_ip="ff05::c"
            up_disc='M-SEARCH * HTTP/1.1\r\nHOST:[{dst}]:1900\r\nST:upnp:rootdevice\r\nMX:2\r\nMAN:"ssdp:discover"\r\n\r\n'.format(dst=dst_ip)
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            #sock.setsockopt(socket.IPPROTO_IP, socket.IPV6_MULTICAST_HOPS, 2)
            if self.debug:print "trying to bind to address:",self.intIP
            socketaddr=socket.getaddrinfo(self.intIP,19110)[-1:][0][-1:][0]
            sock.bind(socketaddr)


            sock.sendto(up_disc, (dst_ip, 1900))

        if self.debug:print "Discovery: ----- tx request -----\n "+up_disc
        sock.settimeout(10.0)
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        sock.close()

        if self.debug:print "Discovery: ----- rx reply -----\n "+data
        descURL=httpparse(StringIO(data)).getheader('location')
        descXMLs=urllib2.urlopen(descURL).read()
        self.pr=urlparse(descURL)
        baseURL=self.pr.scheme+"://"+self.pr.netloc
        dom=minidom.parseString(descXMLs)
        for e in dom.getElementsByTagName('service'):
            stn=e.getElementsByTagName('serviceType')
            if self.igdsvc=="WANIPC":
                target_svctype='urn:schemas-upnp-org:service:WANIPConnection'
            else:
                target_svctype='urn:schemas-upnp-org:service:WANIPv6FirewallControl'
            if stn != []:
                if stn[0].firstChild.nodeValue.strip()[0:-2] == target_svctype:
                    cun=e.getElementsByTagName('controlURL')
                    self.ctrlURL=baseURL+cun[0].firstChild.nodeValue
                    break
        if self.debug: print "control URL is ",self.ctrlURL





    def AddPortMapping(self,intIP,extPort,proto,intPort,enabled=1,duration=0,
                        desc='',remoteHost=''):
        upnp_method='AddPortMapping'
        sendArgs = {'NewPortMappingDescription': (desc, 'string'),
			'NewLeaseDuration': (duration, 'ui4'),
			'NewInternalClient': (intIP, 'string'),
			'NewEnabled': (enabled, 'boolean'),
			'NewExternalPort': (extPort, 'ui2'),
			'NewRemoteHost': (remoteHost, 'string'),
			'NewProtocol': (proto, 'string'),
			'NewInternalPort': (intPort, 'ui2')}
        self.sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPConnection:1',
                self.ctrlURL,upnp_method,sendArgs)


    def DeletePortMapping(self,extPort,proto,remoteHost=''):
        upnp_method='DeletePortMapping'
        sendArgs = {
			'NewExternalPort': (extPort, 'ui2'),
			'NewRemoteHost': (remoteHost, 'string'),
			'NewProtocol': (proto, 'string')}
        self.sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPConnection:1',
                self.ctrlURL,upnp_method,sendArgs)


    def GetExternalIP(self):
        upnp_method='GetExternalIPAddress'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,["NewExternalIPAddress"])

    def GetGenericPortMappingEntry(self,index,hideErr=False):
        upnp_method='GetGenericPortMappingEntry'
        sendArgs={'NewPortMappingIndex': (index, 'ui4'),}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs,hideErr=hideErr)
        if resp_xml != False:
            return get1stTagText(resp_xml,["NewExternalPort","NewRemoteHost",
                                "NewProtocol","NewInternalPort",
                                "NewInternalClient","NewPortMappingDescription",
                                "NewLeaseDuration","NewEnabled"])


    def GetSpecificPortMappingEntry(self,extPort,proto,remote):
        upnp_method='GetSpecificPortMappingEntry'
        sendArgs={
            'NewExternalPort': (extPort, 'ui2'),
			'NewRemoteHost': (remote, 'string'),
			'NewProtocol': (proto, 'string'),
                    }
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewInternalPort",
                                "NewInternalClient","NewPortMappingDescription",
                                "NewLeaseDuration","NewEnabled"])

    def GetNATRSIPStatus(self):
        upnp_method='GetNATRSIPStatus'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewRSIPAvailable",
                                "NewNATEnabled",])

    def GetWarnDisconnectDelay(self):
        upnp_method='GetWarnDisconnectDelay'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewWarnDisconnectDelay",])

    def GetIdleDisconnectTime(self):
        upnp_method='GetIdleDisconnectTime'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewIdleDisconnectTime",])

    def GetAutoDisconnectTime(self):
        upnp_method='GetAutoDisconnectTime'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewAutoDisconnectTime",])

    def GetStatusInfo(self):
        upnp_method='GetStatusInfo'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewConnectionStatus",
                                "NewLastConnectionError",
                                "NewUptime"])

    def SetWarnDisconnectDelay(self,delay):
        upnp_method='SetWarnDisconnectDelay'
        sendArgs={
                    'NewWarnDisconnectDelay': (delay, 'ui4'),
                    }
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)


    def SetIdleDisconnectTime(self,disconnect_time):
        upnp_method='SetIdleDisconnectTime'
        sendArgs={
                    'NewIdleDisconnectTime': (disconnect_time, 'ui4'),
                    }
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)

    def SetAutoDisconnectTime(self,disconnect_time):
        upnp_method='SetAutoDisconnectTime'
        sendArgs={
                    'NewAutoDisconnectTime': (disconnect_time, 'ui4'),
                    }
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)

    def ForceTermination(self):
        upnp_method='ForceTermination'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)

    def RequestTermination(self):
        upnp_method='RequestTermination'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)


    def RequestConnection(self):
        upnp_method='RequestConnection'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)

    def GetConnectionTypeInfo(self):
        upnp_method='GetConnectionTypeInfo'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewConnectionType",
                                "NewPossibleConnectionTypes",])

    def SetConnectionType(self,ctype):
        upnp_method='SetConnectionType'
        sendArgs={
                    'NewConnectionType': (ctype, 'string'),
                    }
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)


    def customAction(self,method_name,in_args={},svc="WANIPConnection"):
        """
        this is for the vendor specific action
        in_args is a dict,
        svc is the IGD service,
        the format is :
            key is the argument name
            value is a two element list, 1st one is the value of arguement, 2nd
            is the UPnP data type defined in the spec. following is an example:
            {'NewPortMappingIndex': [0, 'ui4'],}

        """
        upnp_method=method_name
        sendArgs=dict(in_args)
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:{svc}:1'.format(svc=svc),
            self.ctrlURL,upnp_method,sendArgs)
        return resp_xml


    def sendSOAP(self,hostName,serviceType,controlURL,actionName,
                        actionArguments,hideErr=False):

        """
        send a SOAP request and get the response
        """
        argList = ''
        soapResponse = ''

        if '://' in controlURL:
                urlArray = controlURL.split('/',3)
                if len(urlArray) < 4:
                        controlURL = '/'
                else:
                        controlURL = '/' + urlArray[3]


        soapRequest = 'POST %s HTTP/1.1\r\n' % controlURL

        #Check if a port number was specified in the host name; default is port 80
        if ':' in hostName:
                if not "]" in hostName:
                    hostNameArray = hostName.split(':')
                    host = hostNameArray[0]
                    try:
                            port = int(hostNameArray[1])
                    except:
                            print 'Invalid port specified for host connection:',hostName[1]
                            return False
                else:
                    hostNameArray = hostName.split(']')
                    host = hostNameArray[0][1:]
                    try:
                            port = int(hostNameArray[1][1:])
                    except:
                            print 'Invalid port specified for host connection:',hostName[1]
                            return False
        else:
                host = hostName
                port = 80

        #Create a string containing all of the SOAP action's arguments and values
        for arg,(val,dt) in actionArguments.iteritems():
                argList += '<%s>%s</%s>' % (arg,val,arg)

        #Create the SOAP request
        soapBody =      '<?xml version="1.0"?>'\
                        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'\
                        '<SOAP-ENV:Body>'\
                        '<m:%s xmlns:m="%s">'\
                        '%s'\
                        '</m:%s>'\
                        '</SOAP-ENV:Body>'\
                        '</SOAP-ENV:Envelope>' % (actionName,serviceType,argList,actionName)

        #Specify the headers to send with the request
        headers =       {
                        'Host':hostName,
                        'Content-Length':len(soapBody),
                        'Content-Type':'text/xml',
                        'SOAPAction':'"%s#%s"' % (serviceType,actionName)
                        }

        #Generate the final payload
        for head,value in headers.iteritems():
                soapRequest += '%s: %s\r\n' % (head,value)
        soapRequest += '\r\n%s' % soapBody

        if self.debug:
            print "Action: ---------- tx request -----------"
            if not self.pprint:
                print soapRequest
            else:
                print headers
                xml = minidom.parseString(soapBody)
                print xml.toprettyxml()
            print "Action: -------- end of tx request ------"


        #Send data and go into recieve loop
        if not isv6(self.intIP):
            sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        else:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((host,port))
        sock.send(soapRequest)
        data = sock.recv(8192)
        if not data:
            print "No response!"
            return
        else:
            soapResponse += data
##            if re.compile('<\/.*:envelope>').search(soapResponse.lower()) != None:
##                print "Invalid Response"
##                print data
##                return

##        while True:
##                data = sock.recv(8192)
##                if not data:
##                        break
##                else:
##                        soapResponse += data
##                        if re.compile('<\/.*:envelope>').search(soapResponse.lower()) != None:
##                                break
        sock.close()
        (header,body) = soapResponse.split('\r\n\r\n',1)
        if self.debug == True:
            print "Action: --------rx http response header----------"
            print header
            print "Action: -------- rx http response body----------"
            if not self.pprint:
                print body
            else:
                xml = minidom.parseString(body)
                print xml.toprettyxml()
            print "Action: --------end of rx http response body  -----"
        if not header.upper().startswith('HTTP/1.') or not ' 200 ' in header.split('\r\n')[0]:
            err_code,err_desc=parseErrMsg(body)
            raise UPNPError(header.split('\r\n')[0].split(' ',1)[1],
                err_code,err_desc)
        else:
            return body
##        except Exception, e:
##                if not hideErr: print 'Caught exception:',e
##                sock.close()
##                return False
##
##        except KeyboardInterrupt:
##                print "KeyboardInterrupt"
##                sock.close()
##                return False
##
##

    #following are for IP6FWControl
    def GetFWStatus(self):
        upnp_method='GetFirewallStatus'
        sendArgs={}
        resp_xml=self.sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "FirewallEnabled","InboundPinholeAllowed"])

    def AddPinhole(self,iclient,rhost="",rport=0,iport=0,proto=65535,leasetime=3600):
        upnp_method="AddPinhole"
        pid=getProtoId(proto)
        if pid==False:
            print proto, " is not a supported protocol"
            return
        sendArgs={
        "RemoteHost": (rhost,'string'),
        "RemotePort":(rport,'ui2'),
        "InternalClient": (iclient,'string'),
        "InternalPort":(iport,'ui2'),
        "Protocol":(pid,'ui2'),
        "LeaseTime":(leasetime,'ui4'),
        }
        resp_xml=self.sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
                self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "UniqueID",])

    def GetPinholeTimeout(self,iclient="",rhost="",rport=0,iport=0,proto=65535):
        upnp_method="GetOutboundPinholeTimeout"
        pid=getProtoId(proto)
        if pid==False:
            print proto, " is not a supported protocol"
            return
        sendArgs={
        "RemoteHost": (rhost,'string'),
        "RemotePort":(rport,'ui2'),
        "InternalClient": (iclient,'string'),
        "InternalPort":(iport,'ui2'),
        "Protocol":(pid,'ui2'),
        }
        resp_xml=self.sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
                self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "OutboundPinholeTimeout",])

    def UpdatePinhole(self,uid,lease):
        upnp_method="UpdatePinhole"
        sendArgs={
        "UniqueID": (uid,'ui2'),
        "NewLeaseTime":(lease,'ui4'),
        }
        resp_xml=self.sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
                self.ctrlURL,upnp_method,sendArgs)


    def DelPinhole(self,uid):
        upnp_method="DeletePinhole"
        sendArgs={
        "UniqueID": (uid,'ui2'),
        }
        resp_xml=self.sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
                self.ctrlURL,upnp_method,sendArgs)


    def GetPinholePkts(self,uid):
        upnp_method="GetPinholePackets"
        sendArgs={
        "UniqueID": (uid,'ui2'),
        }
        resp_xml=self.sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
                self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "PinholePackets",])

    def CheckPinhole(self,uid):
        upnp_method="CheckPinholeWorking"
        sendArgs={
        "UniqueID": (uid,'ui2'),
        }
        resp_xml=self.sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPv6FirewallControl:1',
                self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "IsWorking",])

class IGDCMDClient:
    def __init__(self):
        self.igdc=None

    def init(self,args):
        """
        initiate the IGDClient
        """

        self.igdc=IGDClient(args.source,args.url,args.DEBUG,args.pretty_print)



    def addPM(self,args):
        self.igdc.AddPortMapping(args.intIP, args.extPort,
                                    args.proto, args.intPort,
                                    args.enabled,args.duration,
                                    args.desc,args.remote)

    def delPM(self,args):
        self.igdc.DeletePortMapping(args.extPort,
                                    args.proto,args.remote)

    def getExtIP(self,args):
        extip=self.igdc.GetExternalIP()
        print json.dumps(extip,indent=4)

    def getGPM(self,args):
        rlist =[]
        if not args.all:
            pm=self.igdc.GetGenericPortMappingEntry(args.index)
            rlist.append(pm)
        else:
            pm = {}
            i = 0
            while True:
                try:
                    pm=self.igdc.GetGenericPortMappingEntry(i,True)
                except UPNPError as e:
                    if e.code==713:
                        break
                    else:
                        print e
                        return False
                i+=1
                if pm != None:
                    rlist.append(pm)
                else:
                    break
        print json.dumps(rlist,indent=4)

    def getSPM(self,args):

        pm=self.igdc.GetSpecificPortMappingEntry(args.extPort, args.proto,args.remote)
        print json.dumps(pm,indent=4)

    def getNRSS(self,args):

        pm=self.igdc.GetNATRSIPStatus()
        print json.dumps(pm,indent=4)

    def getWDD(self,args):

        pm=self.igdc.GetWarnDisconnectDelay()
        print json.dumps(pm,indent=4)

    def getIDT(self,args):

        pm=self.igdc.GetIdleDisconnectTime()
        print json.dumps(pm,indent=4)

    def getADT(self,args):

        pm=self.igdc.GetAutoDisconnectTime()
        print json.dumps(pm,indent=4)

    def getSI(self,args):

        pm=self.igdc.GetStatusInfo()
        print json.dumps(pm,indent=4)

    def setWDD(self,args):

        self.igdc.SetWarnDisconnectDelay(args.delay)

    def setIDT(self,args):

        self.igdc.SetIdleDisconnectTime(args.time)

    def setADT(self,args):

        self.igdc.SetAutoDisconnectTime(args.time)

    def forceTerm(self,args):

        self.igdc.ForceTermination()

    def requestTerm(self,args):

        self.igdc.RequestTermination()

    def requestConn(self,args):

        self.igdc.RequestConnection()

    def getCT(self,args):

        pm=self.igdc.GetConnectionTypeInfo()
        print json.dumps(pm,indent=4)

    def setCT(self,args):

        self.igdc.SetConnectionType(args.ct_type)

    def custom(self,args):
        print args.input_args
        iargs=json.loads(args.input_args)
        resp_xml=self.igdc.customAction(args.method_name,iargs,args.svc)
        if self.igdc.pprint:
            xml = minidom.parseString(resp_xml)
            print xml.toprettyxml()
        else:
            print resp_xml


    #following are for IPv6FWControl
    def getFWStatus(self,args):
        pm=self.igdc.GetFWStatus()
        print json.dumps(pm,indent=4)

    def addPH(self,args):
        r=self.igdc.AddPinhole(args.intIP,args.rIP,args.rPort,args.intPort,args.proto,args.lease)
        print json.dumps(r,indent=4)


    def getOPHT(self,args):
        r=self.igdc.GetPinholeTimeout(args.intIP,args.rIP,args.rPort,args.intPort,args.proto)
        print json.dumps(r,indent=4)

    def updatePH(self,args):
        self.igdc.UpdatePinhole(args.uid,args.lease)

    def delPH(self,args):
        self.igdc.DelPinhole(args.uid)


    def getPHPkts(self,args):
        r=self.igdc.GetPinholePkts(args.uid)
        print json.dumps(r,indent=4)

    def chkPH(self,args):
        r=self.igdc.CheckPinhole(args.uid)
        print json.dumps(r,indent=4)

def main():
    cli=IGDCMDClient()
    parser = argparse.ArgumentParser(description="UPnP IGD Client by Hu Jun; Implements WANIPConnection and WANIPv6FirewallControl Services")
    parser.add_argument("-d","--DEBUG",action='store_true',
                        help="enable DEBUG output")

    parser.add_argument("-pp","--pretty_print",action='store_true',
                        help="enable xml pretty output for debug and custom action")
    parser.add_argument("-s","--source",required=True,
                        help="source address of requests")
    parser.add_argument("-u","--url",
                        help="control URL")

    subparsers = parser.add_subparsers()

    parser_start = subparsers.add_parser('add',help='add port mapping')
    parser_start.add_argument("intIP",
                        help="Internal IP")
    parser_start.add_argument("intPort",type=int,
                        help="Internal Port")
    parser_start.add_argument("extPort",type=int,
                        help="External Port")
    parser_start.add_argument("proto",choices=['UDP', 'TCP'],
                        help="Protocol")
    parser_start.add_argument("-r","--remote",default="",
                        help="remote host")
    parser_start.add_argument("-d","--desc",default="",
                        help="Description of port mapping")
    parser_start.add_argument("-e","--enabled",type=int,choices=[1, 0],default=1,
                        help="enable or disable port mapping")
    parser_start.add_argument("-du","--duration",type=int,default=0,
                        help="Duration of the mapping")
    parser_start.set_defaults(func=cli.addPM)




    parser_del = subparsers.add_parser('del',help='del port mapping')
    parser_del.add_argument("extPort",type=int,
                        help="External Port")
    parser_del.add_argument("proto",choices=['UDP', 'TCP'],
                        help="Protocol")
    parser_del.add_argument("-r","--remote",default="",
                        help="remote host")
    parser_del.set_defaults(func=cli.delPM)

    parser_geip = subparsers.add_parser('getextip',help='get external IP')
    parser_geip.set_defaults(func=cli.getExtIP)

    parser_gpm = subparsers.add_parser('getgpm',help='get generic pm entry')
    group = parser_gpm.add_mutually_exclusive_group(required=True)

    group.add_argument("-i","--index",type=int,
                        help="index of PM entry")
    group.add_argument("-a","--all",action='store_true',
                        help="list all PM entries")
    parser_gpm.set_defaults(func=cli.getGPM)


    parser_spm = subparsers.add_parser('getspm',help='get specific port mapping')
    parser_spm.add_argument("extPort",type=int,
                        help="External Port")
    parser_spm.add_argument("proto",choices=['UDP', 'TCP'],
                        help="Protocol")
    parser_spm.add_argument("-r","--remote",default="",
                        help="remote host")
    parser_spm.set_defaults(func=cli.getSPM)


    parser_nrss = subparsers.add_parser('getnrss',help='get NAT and RSIP status')
    parser_nrss.set_defaults(func=cli.getNRSS)

    parser_gwdd = subparsers.add_parser('getwdd',help='get warn disconnect delay')
    parser_gwdd.set_defaults(func=cli.getWDD)

    parser_swdd = subparsers.add_parser('setwdd',help='set warn disconnect delay')
    parser_swdd.add_argument("delay",type=int,
                        help="warn disconnect delay")
    parser_swdd.set_defaults(func=cli.setWDD)

    parser_gidt = subparsers.add_parser('getidt',help='get idle disconnect time')
    parser_gidt.set_defaults(func=cli.getIDT)

    parser_sidt = subparsers.add_parser('setidt',help='set idle disconnect time')
    parser_sidt.add_argument("time",type=int,
                        help="idle disconnect time")
    parser_sidt.set_defaults(func=cli.setIDT)

    parser_gadt = subparsers.add_parser('getadt',help='get auto disconnect time')
    parser_gadt.set_defaults(func=cli.getADT)

    parser_sadt = subparsers.add_parser('setadt',help='set auto disconnect time')
    parser_sadt.add_argument("time",type=int,
                        help="auto disconnect time")
    parser_sadt.set_defaults(func=cli.setADT)

    parser_gsi = subparsers.add_parser('getsi',help='get status info')
    parser_gsi.set_defaults(func=cli.getSI)

    parser_rt = subparsers.add_parser('rt',help='request termination')
    parser_rt.set_defaults(func=cli.requestTerm)

    parser_ft = subparsers.add_parser('ft',help='force termination')
    parser_ft.set_defaults(func=cli.forceTerm)

    parser_rc = subparsers.add_parser('rc',help='request connection')
    parser_rc.set_defaults(func=cli.requestConn)

    parser_gct = subparsers.add_parser('getct',help='get connection type info')
    parser_gct.set_defaults(func=cli.getCT)

    parser_sct = subparsers.add_parser('setct',help='set connection type')
    parser_sct.add_argument("ct_type",
                        help="connection type")
    parser_sct.set_defaults(func=cli.setCT)

    parser_cust = subparsers.add_parser('custom',help='use custom action')
    parser_cust.add_argument("method_name",
                        help="name of custom action")
    parser_cust.add_argument("-svc",type=str,
                        choices=['WANIPConnection','WANIPv6FirewallControl'],
                        default="WANIPConnection",
                        help="IGD service, default is WANIPConnection")
    parser_cust.add_argument("-iargs","--input_args",default="{}",
                        help="input args, the format is same as python dict,"\
                         "e.g. '{\"NewPortMappingIndex\": [0, \"ui4\"]}'")
    parser_cust.set_defaults(func=cli.custom)


    #following for IPv6FWControl
    parser_gfwstatus = subparsers.add_parser('getfwstatus',help='get IPv6 FW status')
    parser_gfwstatus.set_defaults(func=cli.getFWStatus)

    parser_addph = subparsers.add_parser('addph',help='add IPv6 FW Pinhole')
    parser_addph.add_argument("intIP",
                        help="Internal IP")
    parser_addph.add_argument("-intPort",type=int,default=0,
                        help="Internal Port")
    parser_addph.add_argument("proto",choices=['UDP', 'TCP','ALL'],
                        help="Protocol")
    parser_addph.add_argument("-rIP",default="",
                        help="Remote IP")
    parser_addph.add_argument("-rPort",type=int,default=0,
                        help="Remote Port")

    parser_addph.add_argument("-lease",type=int,default=3600,
                        help="leasetime of the pinhole")
    parser_addph.set_defaults(func=cli.addPH)


    parser_gopht = subparsers.add_parser('getopht',help='get IPv6 FW OutboundPinholeTimeout')
    parser_gopht.add_argument("-intIP",type=str,default="",
                        help="Internal IP")
    parser_gopht.add_argument("-intPort",type=int,default=0,
                        help="Internal Port")
    parser_gopht.add_argument("-proto",choices=['UDP', 'TCP','ALL'],default='ALL',
                        help="Protocol")
    parser_gopht.add_argument("-rIP",default="",
                        help="Remote IP")
    parser_gopht.add_argument("-rPort",type=int,default=0,
                        help="Remote Port")
    parser_gopht.set_defaults(func=cli.getOPHT)


    parser_uph = subparsers.add_parser('updateph',help='update IPv6 FW pinhole')
    parser_uph.add_argument("uid",type=int,help="UniqueID of the pinhole")
    parser_uph.add_argument("lease",type=int,
                        help="new leasetime of the pinhole")
    parser_uph.set_defaults(func=cli.updatePH)


    parser_dph = subparsers.add_parser('delph',help='delete IPv6 FW pinhole')
    parser_dph.add_argument("uid",type=int,help="UniqueID of the pinhole")
    parser_dph.set_defaults(func=cli.delPH)


    parser_gphpkts = subparsers.add_parser('getphpkts',help='get number of packets go through specified IPv6FW pinhole')
    parser_gphpkts.add_argument("uid",type=int,help="UniqueID of the pinhole")
    parser_gphpkts.set_defaults(func=cli.getPHPkts)


    parser_chkph = subparsers.add_parser('chkph',help='check if the specified pinhole is working')
    parser_chkph.add_argument("uid",type=int,help="UniqueID of the pinhole")
    parser_chkph.set_defaults(func=cli.chkPH)

    args=parser.parse_args()
    cli.init(args)
    cli.igdc.enableDebug(args.DEBUG)
    cli.igdc.enablePPrint(args.pretty_print)
    args.func(args)
if __name__ == '__main__':
    main()
