# knock-out
RAT (Remote Administration Tool) using port-knocking. No TCP/UDP port listening.
libpcap-based server and libnet-based client.


++++++++ KNOCK-OUT ++++++++

This tool will help you to connect remotely to your *NIX-based system without 
the need of a listening port as usual. Instead, the server (knock-outd) will be 
analyzing all the incoming network traffic in order to identify a "triggering" 
pattern of knocked ports, which in turn could be closed or opened by the OS or 
any other application. On the other hand, the client (knock-outc) will send this 
triggering pattern to the specified IP address (server's IP).

knock-out.conf specifies the triggering packets sequence as well as the protocol, 
where "tcp" or "udp" could be used. Once the server has been triggered, one of 
the methods "bind" or "reverse" could be launched to spawn a shell. The "bind" 
method forks a child process that listens in the specified "port", also configured 
in this file, and the "reverse" method returns back a reverse shell on this same 
specified "port" to the origin IP address detected in the incoming packets.

The spawned shell will have root privileges, since it'll be inherited from the parent
process (knock-outd), which evidently must be run as root to use the low-level socket 
interface provided by libpcap.

The client (knock-outc) is the easiest way to knock the ports, however, there
are many other ways to do this easy task such as using scapy or any other network
packet forging tool.


# ++++++++ COMPILATION ++++++++
++++++++ COMPILATION ++++++++

Before compiling it, make sure you have the required libraries installed.
Read the REQUIREMENTS section.

+ Server (knock-outd):
$make server

+ Client (knock-outc):
$make client

+ To clean:
$make clean


++++++++ SUPPORTED PROTOCOLS ++++++++

+ Data Link
Ethernet
Linux Cooked

+ Network
IP

+ Transmision
TCP
UDP


++++++++ REQUIREMENTS ++++++++

+ Server (knock-outd):
libpcap

Debian based systems:
$sudo apt-get install libpcap-dev

Manual download and compilation:
http://www.tcpdump.org


+ Client (knock-outc):
libnet

Debian based systems:
$sudo apt-get install libnet1-dev

Manual download and compilation:
https://sourceforge.net/projects/libnet-dev/


++++++++ AUTHOR ++++++++
| Name:      Alejandro Hernandez (nitr0us)
| Twitter:   @nitr0usmx
| Email:     nitrousenador [at] gmail [dot] com
| Website:   http://www.brainoverflow.org
| Blog:      http://chatsubo-labs.blogspot.mx
| Location:

         .
         \'~~~-,
          \    '-,_
           \ /\    `~'~''\          M E X I C O
           _\ \\          \/~\
           \__ \\             \
              \ \\.             \
               \ \ \             `~~
                '\\ \.             /
                 / \  \            |
                  \_\  \           |             _.----,
                        |           \           !     /
                       '._           \_      __/    _/
                          \_           ''--''    __/
                            \.__                |
                                ''.__  __.._ o<-_\---- here !
                                     ''     './  `
