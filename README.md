# pyigdc

This is a UPnP IGDv1 command line client/lib in python.

All IGDv1 actions are supported.

Target for developer and protocol testing.

## Installation

Require python 2.6 or later (python3 is not supported)

Should be able to run on both Windows and *nix

## Usage as a Command Line Client

```
python igdc.py -h
usage: igdc.py [-h] [-d] -s SOURCE [-u URL]
               {add,del,getextip,getgpm,getspm,getnrss,getwdd,setwdd,getidt,setidt,getadt,setadt,getsi,rt,ft,rc,getct,setct}
               ...

UPnP IGD Client by Hu Jun

positional arguments:
  {add,del,getextip,getgpm,getspm,getnrss,getwdd,setwdd,getidt,setidt,getadt,setadt,getsi,rt,ft,rc,getct,setct}
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

optional arguments:
  -h, --help            show this help message and exit
  -d, --DEBUG           enable DEBUG output
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


## Usage as a Library
from igdc import IGDClient

see comments in igdc.py for detail usage



## License
MIT
