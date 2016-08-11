simplemux
=========

There are some situations in which multiplexing a number of small packets into a bigger one is desirable. For example, a number of small packets can be sent together between a pair of machines if they share a common network path. Thus, the traffic profile can be shifted from small to larger packets, reducing the network overhead and the number of packets per second to be managed by intermediate routers.

Simplemux is a protocol able to encapsulate a number of packets belonging to different protocols into a single packet. It includes the "Protocol" field on each multiplexing header, thus allowing the inclusion of a number of packets belonging to different protocols on a packet of another protocol.

The specification of Simplemux is here: http://datatracker.ietf.org/doc/draft-saldana-tsvwg-simplemux/. It has been proposed to the Transpor Area Working Group of the IETF (https://datatracker.ietf.org/wg/tsvwg/documents/)

The size of the multiplexing headers is kept very low (it may be a single byte when multiplexing small packets) in order to reduce the overhead.

This page includes an implementation of Simplemux written in C for Linux. It uses simplemux as the multiplexing protocol, and IP and ROHC as multiplexed protocols. Two options are considered for the tunneling protocol:
 - Network mode: IP is used for tunneling (with Protocol Number 253)
 - Transport mode: IP/UDP is used for tunneling (with a common UDP port)

ROCH feedback messages are always sent in IP/UDP packets.

A research paper about Simplemux can be found here: http://diec.unizar.es/~jsaldana/personal/chicago_CIT2015_in_proc.pdf

A presentation about Simplemux can be found here: http://es.slideshare.net/josemariasaldana/simplemux-traffic-optimization

This work has been partially financed by the EU H2020 Wi-5 project (G.A. no: 644262, see http://www.wi5.eu/), and the Spanish Ministry of Economy and Competitiveness project TIN2015-64770-R, in cooperation with the European Regional Development Fund.
