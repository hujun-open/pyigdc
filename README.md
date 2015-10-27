# pyigdc

This is a UPnP IGD command line client/lib in python.
Support following services:

* WANIPConnection v1
  * Vendor specific action could be supported via "custom" action.
* WANIPv6FirewallControl v1



Target for developer and protocol testing.

## Installation

Require python 2.7 (python3 is not supported)

Should be able to run on both Windows and *nix

## Usage as a Command Line Client

```
python igdc.py -h
usage: igdc.py [-h] [-d] [-pp] -s SOURCE [-u URL]
               {add,del,getextip,getgpm,getspm,getnrss,getwdd,setwdd,getidt,setidt,getadt,setadt,getsi,rt,ft,rc,getct,setct,custom,getfwstatus,addph,getopht,updateph,delph,getphpkts,chkph}
               ...

UPnP IGD Client by Hu Jun Implements WANIPConnection and
WANIPv6FirewallControl Services

positional arguments:
  {add,del,getextip,getgpm,getspm,getnrss,getwdd,setwdd,getidt,setidt,getadt,setadt,getsi,rt,ft,rc,getct,setct,custom,getfwstatus,addph,getopht,updateph,delph,getphpkts,chkph}
    add                 add port mapping
    del                 del port mapping
    getextip            get external IP
    getgpm              get generic pm entry
    getspm              get specific port mapping
    getnrss             get NAT and RSIP status
    getwdd              get warn disconnect delay
    setwdd              set warn disconnect delay
    getidt              get idle disconnect time
    setidt              set idle disconnect time
    getadt              get auto disconnect time
    setadt              set auto disconnect time
    getsi               get status info
    rt                  request termination
    ft                  force termination
    rc                  request connection
    getct               get connection type info
    setct               set connection type
    custom              use custom action
    getfwstatus         get IPv6 FW status
    addph               add IPv6 FW Pinhole
    getopht             get IPv6 FW OutboundPinholeTimeout
    updateph            update IPv6 FW pinhole
    delph               delete IPv6 FW pinhole
    getphpkts           get number of packets go through specified IPv6FW
                        pinhole
    chkph               check if the specified pinhole is working

optional arguments:
  -h, --help            show this help message and exit
  -d, --DEBUG           enable DEBUG output
  -pp, --pretty_print   enable xml pretty output for debug and custom action
  -s SOURCE, --source SOURCE
                        source address of requests
  -u URL, --url URL     control URL

```
add -h after each action to see help for the specific action:
```
python igdc.py add -h
usage: igdc.py add [-h] [-r REMOTE] [-d DESC] [-e {1,0}] [-du DURATION]
                   intIP intPort extPort {UDP,TCP}

positional arguments:
  intIP                 Internal IP
  intPort               Internal Port
  extPort               External Port
  {UDP,TCP}             Protocol

optional arguments:
  -h, --help            show this help message and exit
  -r REMOTE, --remote REMOTE
                        remote host
  -d DESC, --desc DESC  Description of port mapping
  -e {1,0}, --enabled {1,0}
                        enable or disable port mapping
  -du DURATION, --duration DURATION
                        Duration of the mapping
```
all getxxx action's output is in json format

## Use Custom Action for WANIPConnection
```
python igdc.py custom -h
usage: igdc.py custom [-h] [-iargs INPUT_ARGS] method_name

positional arguments:
  method_name           name of custom action

optional arguments:
  -h, --help            show this help message and exit
  -iargs INPUT_ARGS, --input_args INPUT_ARGS
                        input args, the format is same as python dict,e.g.
                        '{"NewPortMappingIndex": [0, "ui4"]}'
```
method_name is the name of the action defined in the IGD service description XML.

-iargs specify a list of input arguments to the action,the format  is same as python dict:
*  key is the argument name
*  value is a two element list, 1st one is the value of arguement, 2nd one is the UPnP data type defined in the service description XML

The ouput of this action is the responed XML from the server.

An example to use custom action achieve action:GetGenericPortMappingEntry
```
python igdc.py -pp -s 40.0.0.100 custom GetGenericPortMappingEntry -iargs '{"NewPortMappingIndex": [0, "ui4"]}'
<?xml version="1.0" ?>
<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
	<s:Body>
		<u:GetGenericPortMappingEntryResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
			<NewRemoteHost/>
			<NewExternalPort>2100</NewExternalPort>
			<NewProtocol>TCP</NewProtocol>
			<NewInternalPort>2100</NewInternalPort>
			<NewInternalClient>40.0.0.100</NewInternalClient>
			<NewEnabled>1</NewEnabled>
			<NewPortMappingDescription/>
			<NewLeaseDuration>0</NewLeaseDuration>
		</u:GetGenericPortMappingEntryResponse>
	</s:Body>
</s:Envelope>
```



## Usage as a Library
from igdc import IGDClient

see comments in igdc.py for detail usage



## License
MIT
