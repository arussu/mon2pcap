# mon2pcap

_mon2pcap_ is a program for converting Cisco's StarOS "monitor subscriber" or "monitor protocol" text based packet captures to PCAP.  
This program will work only if the PDU Hexdump switch (X or A) is enabled.

## Disclaimer
This program comes with no guarantees whatsoever.  
The hexdump in the monsub does __NOT__ represent a full packet, hence:    
⚠️ All data-link layer protocols are generated, the MACs there are bogus.  
⚠️ All non-IP packets data-link, network and transport protocols are bogus.  
⚠️ If it's IP packet, the ports are correct (most of the time) but the transport level protocol is bogus.  
The layers had to be generated for wireshark and other tools working with pcap file formats to properly dissect them.  

## Installation
### Prerequisites
- [Python 3.6+](https://www.python.org/downloads/)  
  ⚠️ Installers usually ask to add Python to `PATH`, do it now and you will avoid headaches later. 
- [pip - The Python Package Installer](https://pip.pypa.io/en/stable/installation/)
- _mon2pcap_ installation:
  ```
  $ pip install mon2pcap
  ```

## Usage
```
$ mon2pcap --help
usage: mon2pcap [-h] -i <infile> [-o <outfile>]
                [-e {GTPC,GTPCv2,GTPU,RADIUS,USERL3,USERL3_IPV6,CSS,DIAMETER,RANAP...}]
                [-s] [-v] [-d]

Convert StarOS "monitor subscriber" or "monitor protocol" ASCII dump to PCAP

options:
  -h, --help            show this help message and exit
  -i <infile>, --input <infile>
                        input file
  -o <outfile>, --output <outfile>
                        output file
  -e {GTPC,GTPCv2,GTPU,RADIUS,USERL3,USERL3_IPV6,CSS,DIAMETER,RANAP...}
                        exclude one or more protocols
  -s, --skip-malformed  Skip malformed packets
  -v, --version         show program's version number and exit
  -d, --debug           debug level logging
```

```
$  mon2pcap -i test_mon_sub.txt
100%|██████████████████████████████████████████████████████| 1746/1746 [00:00<00:00, 237876.14 lines/s]
PCAP generated at "test_mon_sub.pcap"

Found #14 valid packets
========================
 GTPC         : 4
 DIAMETER     : 4
 PFCP         : 4
 GTPP         : 2
 Ignored      : 4
 ```

## License
[GPLv3]('./LICENSE')
