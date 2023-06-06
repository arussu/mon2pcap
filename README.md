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
- [Python 3.8.1 or newer](https://www.python.org/downloads/)  
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

## Implemented protocols
SPGW/GGSN/SAEGW:
 - `GTPC        (24)` ON  by default
 - `EGTPC       (74)` ON  by default
 - `Radius Auth (13)` ON  by default
 - `Radiu Acct  (14)` ON  by default
 - `EC Diameter (36)` ON  by default
 - `GTPU        (26)` OFF by default
 - `User L3     (19)` OFF by default
 - `CSS Data    (34)` OFF by default
 - `IPSec IKEv2 (40)` OFF by default
 - `DNS Client  (70)` OFF by default
 - `L2TP        (21)` ON  by default
 - `Radius COA  (31)` OFF by default 
 - `DHCP        (28)` OFF by default 
 - `L3 Tunnel   (33)` OFF by default //tested with GRE
 - `PFCP        (49)` ON  by default
 - `GTPP        (27)` ON  by default
 - `LMISF       (39)` OFF by default

---
MME/SGSN:
  - `GTPC       (24)` ON  by default
  - `S1AP       (81)` ON  by default
  - `DIAMETER   (36)` ON  by default
  - `RANAP      (56)` OFF by default
  - `BSSGP      (59)` OFF by default
  - `TCAP       (54)` OFF by default
  - `SCCP       (53)` OFF by default
  - `SLS        (94)` ON  by default
  - `SCTP       (51)` OFF by default

## Changelog
[CHANGELOG](CHANGELOG.md)

## License
[GPLv3](LICENSE)
