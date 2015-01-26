#!/usr/bin/env python


#-------------------------------------------------------------------------------
# Name:        A UPNP IGD v1 Client
# Desc:        Could be used as CLI client or a client lib. to use it as lib,
#              use class IGDClient
#
# Author:      Hu Jun
#
# Created:     1/26/2015
# Copyright:   (c) Hu Jun 2015
# Licence:     GPLv2
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

DEBUG=False

def str2bool(bstr):
    return bool(int(bstr))

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
}



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
    err_code=dom.getElementsByTagName('errorCode')[0].firstChild.nodeValue
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
def sendSOAP(hostName,serviceType,controlURL,actionName,actionArguments,hideErr=False):
        global DEBUG
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
                hostNameArray = hostName.split(':')
                host = hostNameArray[0]
                try:
                        port = int(hostNameArray[1])
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
        soapBody =      '<?xml version="1.0"?>\n'\
                        '<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope" SOAP-ENV:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">\n'\
                        '<SOAP-ENV:Body>\n'\
                        '\t<m:%s xmlns:m="%s">\n'\
                        '%s\n'\
                        '\t</m:%s>\n'\
                        '</SOAP-ENV:Body>\n'\
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

        if DEBUG:
            print "Action: ---------- tx request -----------"
            print soapRequest
            print "Action: -------- end of tx request ------"
        #Send data and go into recieve loop
        try:
                sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
                sock.connect((host,port))
                sock.send(soapRequest)
                while True:
                        data = sock.recv(8192)
                        if not data:
                                break
                        else:
                                soapResponse += data
                                if re.compile('<\/.*:envelope>').search(soapResponse.lower()) != None:
                                        break
                sock.close()
                (header,body) = soapResponse.split('\r\n\r\n',1)
                if DEBUG == True:
                    print "Action: --------rx http response header----------"
                    print header
                    print "Action: -------- rx http response body----------"
                    print body
                    print "Action: --------end of rx http response body  -----"
                if not header.upper().startswith('HTTP/1.') or not ' 200 ' in header.split('\r\n')[0]:
                    err_code,err_desc=parseErrMsg(body)
                    raise RuntimeError(
                    "Request failed with http {http_err}\nUPnP error code: {code}, description: {desc}".
                    format(http_err=header.split('\r\n')[0].split(' ',1)[1],
                    code=err_code,desc=err_desc))

                else:
                        return body
        except Exception, e:
                if not hideErr: print 'Caught exception:',e
                sock.close()
                return False
        except KeyboardInterrupt:
                print ""
                sock.close()
                return False




class IGDClient:
    """
    UPnP IGD v1 Client class, supports all actions
    """
    def __init__(self, intIP,ctrlURL=None):
        """
        - intIP is the source address of the request packet, which implies the source interface
        - ctrlURL is the the control URL of IGD server, client will do discovery if it is None
        - all Getxxx action returns a json string
        """
        self.intIP=intIP #the source addr of the client
        self.ctrlURL=ctrlURL
        if self.ctrlURL == None:
            self.discovery()

    def discovery(self):
        """
        Find IGD device and its control URL via UPnP multicast discovery
        """
        up_disc='M-SEARCH * HTTP/1.1\r\nHOST:239.255.255.250:1900\r\nST:upnp:rootdevice\r\nMX:2\r\nMAN:"ssdp:discover"\r\n\r\n'
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.bind((self.intIP,19110))
        sock.sendto(up_disc, ("239.255.255.250", 1900))
        if DEBUG:print "Discovery: ----- tx request -----\n "+up_disc
        sock.settimeout(10.0)
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        sock.close()
        if DEBUG:print "Discovery: ----- rx reply -----\n "+data
        descURL=httpparse(StringIO(data)).getheader('location')
        descXMLs=urllib2.urlopen(descURL).read()
        self.pr=urlparse(descURL)
        baseURL=self.pr.scheme+"://"+self.pr.netloc
        dom=minidom.parseString(descXMLs)
        for e in dom.getElementsByTagName('service'):
            stn=e.getElementsByTagName('serviceType')
            if stn != []:
                if stn[0].firstChild.nodeValue == 'urn:schemas-upnp-org:service:WANIPConnection:1':
                    cun=e.getElementsByTagName('controlURL')
                    self.ctrlURL=baseURL+cun[0].firstChild.nodeValue
                    break


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
        sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPConnection:1',
                self.ctrlURL,upnp_method,sendArgs)


    def DeletePortMapping(self,extPort,proto,remoteHost=''):
        upnp_method='DeletePortMapping'
        sendArgs = {
			'NewExternalPort': (extPort, 'ui2'),
			'NewRemoteHost': (remoteHost, 'string'),
			'NewProtocol': (proto, 'string')}
        sendSOAP(self.pr.netloc,
                'urn:schemas-upnp-org:service:WANIPConnection:1',
                self.ctrlURL,upnp_method,sendArgs)


    def GetExternalIP(self):
        upnp_method='GetExternalIPAddress'
        sendArgs={}
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        dom=minidom.parseString(resp_xml)
        return dom.getElementsByTagName('NewExternalIPAddress')[0].firstChild.nodeValue

    def GetGenericPortMappingEntry(self,index,hideErr=False):
        upnp_method='GetGenericPortMappingEntry'
        sendArgs={'NewPortMappingIndex': (index, 'ui4'),}
        resp_xml=sendSOAP(self.pr.netloc,
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
        resp_xml=sendSOAP(self.pr.netloc,
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
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewRSIPAvailable",
                                "NewNATEnabled",])

    def GetWarnDisconnectDelay(self):
        upnp_method='GetWarnDisconnectDelay'
        sendArgs={}
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewWarnDisconnectDelay",])

    def GetIdleDisconnectTime(self):
        upnp_method='GetIdleDisconnectTime'
        sendArgs={}
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewIdleDisconnectTime",])

    def GetAutoDisconnectTime(self):
        upnp_method='GetAutoDisconnectTime'
        sendArgs={}
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)
        if resp_xml != False:
            return get1stTagText(resp_xml,[
                                "NewAutoDisconnectTime",])

    def GetStatusInfo(self):
        upnp_method='GetStatusInfo'
        sendArgs={}
        resp_xml=sendSOAP(self.pr.netloc,
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
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)


    def SetIdleDisconnectTime(self,disconnect_time):
        upnp_method='SetIdleDisconnectTime'
        sendArgs={
                    'NewIdleDisconnectTime': (disconnect_time, 'ui4'),
                    }
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)

    def SetAutoDisconnectTime(self,disconnect_time):
        upnp_method='SetAutoDisconnectTime'
        sendArgs={
                    'NewAutoDisconnectTime': (disconnect_time, 'ui4'),
                    }
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)

    def ForceTermination(self):
        upnp_method='ForceTermination'
        sendArgs={}
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)

    def RequestTermination(self):
        upnp_method='RequestTermination'
        sendArgs={}
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)


    def RequestConnection(self):
        upnp_method='RequestConnection'
        sendArgs={}
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)

    def GetConnectionTypeInfo(self):
        upnp_method='GetConnectionTypeInfo'
        sendArgs={}
        resp_xml=sendSOAP(self.pr.netloc,
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
        resp_xml=sendSOAP(self.pr.netloc,
            'urn:schemas-upnp-org:service:WANIPConnection:1',
            self.ctrlURL,upnp_method,sendArgs)



def addPM(args):
    igdc=IGDClient(args.source,args.url)
    igdc.AddPortMapping(args.intIP, args.extPort, args.proto, args.intPort,
                         args.enabled,
                            args.duration, args.desc,args.remote)

def delPM(args):
    igdc=IGDClient(args.source,args.url)
    igdc.DeletePortMapping(args.extPort, args.proto,args.remote)

def getExtIP(args):
    igdc=IGDClient(args.source,args.url)
    extip=igdc.GetExternalIP()
    print extip

def getGPM(args):
    igdc=IGDClient(args.source,args.url)
    rlist =[]
    if not args.all:
        pm=igdc.GetGenericPortMappingEntry(args.index)
        rlist.append(pm)
    else:
        pm = {}
        i = 0
        while True:
            pm=igdc.GetGenericPortMappingEntry(i,True)
            i+=1
            if pm != None:
                rlist.append(pm)
            else:
                break
    print json.dumps(rlist,indent=4)

def getSPM(args):
    igdc=IGDClient(args.source,args.url)
    pm=igdc.GetSpecificPortMappingEntry(args.extPort, args.proto,args.remote)
    print json.dumps(pm,indent=4)

def getNRSS(args):
    igdc=IGDClient(args.source,args.url)
    pm=igdc.GetNATRSIPStatus()
    print json.dumps(pm,indent=4)

def getWDD(args):
    igdc=IGDClient(args.source,args.url)
    pm=igdc.GetWarnDisconnectDelay()
    print json.dumps(pm,indent=4)

def getIDT(args):
    igdc=IGDClient(args.source,args.url)
    pm=igdc.GetIdleDisconnectTime()
    print json.dumps(pm,indent=4)

def getADT(args):
    igdc=IGDClient(args.source,args.url)
    pm=igdc.GetAutoDisconnectTime()
    print json.dumps(pm,indent=4)

def getSI(args):
    igdc=IGDClient(args.source,args.url)
    pm=igdc.GetStatusInfo()
    print json.dumps(pm,indent=4)

def setWDD(args):
    igdc=IGDClient(args.source,args.url)
    igdc.SetWarnDisconnectDelay(args.delay)

def setIDT(args):
    igdc=IGDClient(args.source,args.url)
    igdc.SetIdleDisconnectTime(args.time)

def setADT(args):
    igdc=IGDClient(args.source,args.url)
    igdc.SetAutoDisconnectTime(args.time)

def forceTerm(args):
    igdc=IGDClient(args.source,args.url)
    igdc.ForceTermination()

def requestTerm(args):
    igdc=IGDClient(args.source,args.url)
    igdc.RequestTermination()

def requestConn(args):
    igdc=IGDClient(args.source,args.url)
    igdc.RequestConnection()

def getCT(args):
    igdc=IGDClient(args.source,args.url)
    pm=igdc.GetConnectionTypeInfo()
    print json.dumps(pm,indent=4)

def setCT(args):
    igdc=IGDClient(args.source,args.url)
    igdc.SetConnectionType(args.ct_type)

def main():
    global DEBUG
    parser = argparse.ArgumentParser(description="UPnP IGDv1 Client by Hu Jun")
    parser.add_argument("-d","--DEBUG",action='store_true',
                        help="enable DEBUG output")
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
    parser_start.set_defaults(func=addPM)


    parser_del = subparsers.add_parser('del',help='del port mapping')
    parser_del.add_argument("extPort",type=int,
                        help="External Port")
    parser_del.add_argument("proto",choices=['UDP', 'TCP'],
                        help="Protocol")
    parser_del.add_argument("-r","--remote",default="",
                        help="remote host")
    parser_del.set_defaults(func=delPM)

    parser_geip = subparsers.add_parser('getextip',help='get external IP')
    parser_geip.set_defaults(func=getExtIP)

    parser_gpm = subparsers.add_parser('getgpm',help='get generic pm entry')
    group = parser_gpm.add_mutually_exclusive_group(required=True)

    group.add_argument("-i","--index",type=int,
                        help="index of PM entry")
    group.add_argument("-a","--all",action='store_true',
                        help="list all PM entries")
    parser_gpm.set_defaults(func=getGPM)


    parser_spm = subparsers.add_parser('getspm',help='get specific port mapping')
    parser_spm.add_argument("extPort",type=int,
                        help="External Port")
    parser_spm.add_argument("proto",choices=['UDP', 'TCP'],
                        help="Protocol")
    parser_spm.add_argument("-r","--remote",default="",
                        help="remote host")
    parser_spm.set_defaults(func=getSPM)


    parser_nrss = subparsers.add_parser('getnrss',help='get NAT and RSIP status')
    parser_nrss.set_defaults(func=getNRSS)

    parser_gwdd = subparsers.add_parser('getwdd',help='get warn disconnect delay')
    parser_gwdd.set_defaults(func=getWDD)

    parser_swdd = subparsers.add_parser('setwdd',help='set warn disconnect delay')
    parser_swdd.add_argument("delay",type=int,
                        help="warn disconnect delay")
    parser_swdd.set_defaults(func=setWDD)

    parser_gidt = subparsers.add_parser('getidt',help='get idle disconnect time')
    parser_gidt.set_defaults(func=getIDT)

    parser_sidt = subparsers.add_parser('setidt',help='set idle disconnect time')
    parser_sidt.add_argument("time",type=int,
                        help="idle disconnect time")
    parser_sidt.set_defaults(func=setIDT)

    parser_gadt = subparsers.add_parser('getadt',help='get auto disconnect time')
    parser_gadt.set_defaults(func=getADT)

    parser_sadt = subparsers.add_parser('setadt',help='set auto disconnect time')
    parser_sadt.add_argument("time",type=int,
                        help="auto disconnect time")
    parser_sadt.set_defaults(func=setADT)

    parser_gsi = subparsers.add_parser('getsi',help='get status info')
    parser_gsi.set_defaults(func=getSI)

    parser_rt = subparsers.add_parser('rt',help='request termination')
    parser_rt.set_defaults(func=requestTerm)

    parser_ft = subparsers.add_parser('ft',help='force termination')
    parser_ft.set_defaults(func=forceTerm)

    parser_rc = subparsers.add_parser('rc',help='request connection')
    parser_rc.set_defaults(func=requestConn)

    parser_gct = subparsers.add_parser('getct',help='get connection type info')
    parser_gct.set_defaults(func=getCT)

    parser_sct = subparsers.add_parser('setct',help='set connection type')
    parser_sct.add_argument("ct_type",
                        help="connection type")
    parser_sct.set_defaults(func=setCT)

    args=parser.parse_args()
    DEBUG=args.DEBUG
    args.func(args)
if __name__ == '__main__':
    main()
