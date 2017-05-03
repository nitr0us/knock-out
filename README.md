# knock-out

A RAT (Remote Administration Tool) using port-knocking techniques for *NIX systems.
No TCP/UDP port listening. libpcap-based server and libnet-based client.

<img src="http://brainoverflow.org/misc/knock-out.png" width="100" height="100" />
foo

![Screenshot](http://brainoverflow.org/misc/knock-out.png)

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


################## Compilation ##################

Before compiling it, make sure you have the required libraries installed.
Read the Requirements section.

+ Server (knock-outd):
$make server

+ Client (knock-outc):
$make client

+ To clean:
$make clean


################## Usage ##################

+ knock-out.conf
The server (knock-outd) and the client (knock-outc) use the same configuration file,
knock-out.conf.

Modify this config file according to your needs. Following a brief description of 
each customizable parameter in it:

Protocol: transport protocol to use. Accepted values: "tcp" or "udp".

Sequence: three and only three ports separated by commas that must be knocked before 
          launching a shell. Accepted values: from 1 to 65535.

Timeout:  maximum time in seconds between each port knock. If this timeout is reached 
          the sequence is broken and the port knocking process must be started from
          the first port specified in "Sequence".

Method:   method to spawn a shell. Accepted values: "bind" or "reverse".

Port:     if the chosen method is "bind", a new shell will be listening in this port.
          if the method is "reverse", then a shell will be spawned to the client IP on 
          this port. The client must have this TCP port listening (knock-outc does it
          by default)


+ Server (knock-outd)
$sudo ./knock-outd knock-out.conf <interface>

+ Client (knock-outc)
$sudo ./knock-outc knock-out.conf <SERVER-IP>

+ knock-out.h
Each port knock on the specified "Sequence" must have the defined flags in knock-out.h.

By default, the following flags must be enabled on each packet if the "Protocol" used
is TCP:
#define FLAG_KNOCK_TCP          TH_RST
#define VALID_FLAGS(flags)    ((flags & FLAG_KNOCK_TCP) ? 1 : 0)

Therefore, all the packets must have the RST (Reset) flag enabled, if TCP used.


################## Supported Protocols ##################

+ Data Link
  - Ethernet
  - Linux Cooked

+ Network
  - IP

+ Transmision
  - TCP
  - UDP


################## Requirements ##################

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


################## Author ##################

Alejandro Hernandez
@nitr0usmx
http://wwww.brainoverflow.org
http://chatsubo-labs.blogspot.mx
Location:

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


################## Final Notes ##################

I originally wrote this code in 2006, but everything was in Spanish.
11 years later I found out that this old code still works perfectly
with the current versions of libpcap and libnet, so I thought I'd be 
cool to translate it.

Original code: http://brainoverflow.org/code/knock-out/knock-out.tar.gz
