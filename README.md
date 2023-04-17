## Packet Sniffer

### Introduction
This project is an implementation of a small and simple packet sniffer, implemented in C#. The packet sniffer application `ipk-sniffer` was build using *sharppacap* library and
supports filtering a few different protocol and frame types, which will be listed bellow.

### Build
This application is build using dotnet. However we also include a simple `Makefile` to make the build process of the application itself even simpler on linux.
Therefore to build the application on linux, simply run:
> make

To build the application on other platforms, which do not support make, use `dotnet release`.

### Usage

#### Execution
After building, the application is used as follows.
> ./ipk-sniffer [-i interface | --interface interface] {-p port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num}

Where:
`-i` eth0 (just one interface to sniff) or `--interface`. If this parameter is not specified (and any other parameters as well), or if only -i/--interface is specified without a value (and any other parameters are unspecified), a list of active interfaces is printed (additional information beyond the interface list is welcome but not required).  
`-t or --tcp` (will display TCP segments and is optionally complemented by -p functionality).  
`-u or --udp` (will display UDP datagrams and is optionally complemented by-p functionality).  
`-p port_number` (extends previous two parameters to filter TCP/UDP based on port number; if this parameter is not present, then no filtering by port number occurs; if the parameter is given, the given port can occur in both the source and destination part of TCP/UDP headers).  
`--icmp4` (will display only ICMPv4 packets).  
`--icmp6` (will display only ICMPv6 echo request/response).  
`--arp` (will display only ARP frames).  
`--ndp` (will display only ICMPv6 NDP packets).  
`--igmp` (will display only IGMP packets).  
`--mld` (will display only MLD packets).  
Unless protocols are explicitly specified, all (i.e., all content, regardless of protocol) are considered for printing.  
`-n packet_count` (specifies the number of packets to display, i.e., the "time" the program runs; if not specified, consider displaying only one packet, i.e., as if -n 1)  

** This information can also be displayed by using --help**
Upon exit, either organically or using SIGINT, the application complies with standard bash exit codes
@cite exit_codes_with_special_meanings

#### Output
Non-printable characters are replaced with period.
Output format:
> timestamp: time
> src MAC: MAC address with : as separator
> dst MAC: MAC address with : as separator
> frame length: length
> src IP: IP address if any (support v4 but also v6 representation according to RFC5952)
> dst IP: IP address if any (support v4 but also v6 representation according to RFC5952)
> src port: port number if any
> dst port: port number if any
> byte_offset: byte_offset_hexa byte_offset_ASCII
whereby:
    * time is in RFC 3339 format
    * length is in bytes

### Implementation
In this section, we describe some of the implementation details and specifics.


### Dependecies
The project uses these NuGet packages also included in *.csproj* file.

 * PackageReference Include="CommandLineParser" Version="2.9.1"  
 * PackageReference Include="PacketDotNet" Version="1.4.7"  
 * PackageReference Include="SharpPcap" Version="6.2.5"  

### Design and Implementation
The application was designed using Singleton design pattern for class Sniffer, which handles the biggest part of it. It builds on the sharppacap library for packet capturing.
Application operates in a way which we think allows for fast processing of incoming packets, as the main thread only enqueues incoming packets into a blocking queue and then the processing thread
takes these packets one by one. Therefore the actual packet capturing is not slowed down by expensive operations, such as IO and packet parsing.

#### Device and packet filtering
Firstly, the device specified by interface parameter is opened and then filtering parameters are considered for building the final filter. The final filter is an "OR" of the separate filters, described bellow.  

TCP and UDP filters:  
> ( TCP )
> ( TCP port port_number)
Or  
> ( UDP )
> ( UDP port port_number )  

@cite capturefilters  

ICMPv4, ICMPv6 and ARP filters:  
> ( icmp)
> ( icmp6 )
> ( arp )  

NDP filter:  
> ( icmp6[icmp6type] = icmp6-neighborsolicit or icmp6[icmp6type] = icmp6-routersolicit or icmp6[icmp6type] = icmp6-routeradvert or icmp6[icmp6type] = icmp6-neighboradvert or icmp6[icmp6type] = icmp6-redirect )  
@cite narten_nordmark_simpson_soliman_1970

MLD filter:  
> ( icmp6[icmp6type] = icmp6-multicastlistenerquery or icmp6[icmp6type] = icmp6-multicastlistenerreportv1 or icmp6[icmp6type] = icmp6-multicastlistenerreportv2 or icmp6[icmp6type] = icmp6-multicastlistenerdone )  
@cite deering_fenner_haberman_1999
