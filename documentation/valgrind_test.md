# Valgrind test
31/10/2024

Compile Simplemux with `-g`:
```
$ gcc -o simplemux3 -g -Wall $(pkg-config rohc --cflags) ./src/simplemux.c $(pkg-config rohc --libs )
```

Run this command in a virtual machine (Simplemux blast flavor with tap in UDP mode):
```
root@debianvm2:/home/jmsaldana# valgrind ./simplemux/simplemux3 -i tap0 -e ens33 -M udp -T tap -c 192.168.129.129 -d 2 -b -P 100000
```

And the equivalent command in the other machine.

I send some pings:
``` 
root@debianvm2:/home/jmsaldana# ping 192.168.200.1
PING 192.168.200.1 (192.168.200.1) 56(84) bytes of data.
64 bytes from 192.168.200.1: icmp_seq=1 ttl=64 time=99.5 ms
64 bytes from 192.168.200.1: icmp_seq=2 ttl=64 time=28.6 ms
64 bytes from 192.168.200.1: icmp_seq=3 ttl=64 time=28.8 ms
64 bytes from 192.168.200.1: icmp_seq=4 ttl=64 time=27.5 ms
64 bytes from 192.168.200.1: icmp_seq=5 ttl=64 time=21.9 ms
64 bytes from 192.168.200.1: icmp_seq=6 ttl=64 time=80.2 ms
64 bytes from 192.168.200.1: icmp_seq=7 ttl=64 time=35.1 ms
64 bytes from 192.168.200.1: icmp_seq=8 ttl=64 time=53.2 ms
64 bytes from 192.168.200.1: icmp_seq=9 ttl=64 time=58.0 ms
64 bytes from 192.168.200.1: icmp_seq=10 ttl=64 time=74.1 ms
64 bytes from 192.168.200.1: icmp_seq=11 ttl=64 time=77.5 ms
64 bytes from 192.168.200.1: icmp_seq=12 ttl=64 time=63.4 ms
64 bytes from 192.168.200.1: icmp_seq=13 ttl=64 time=49.6 ms
64 bytes from 192.168.200.1: icmp_seq=14 ttl=64 time=53.3 ms
```

When I finish Simplemux, I see this:
```
 Sending a blast ACK
 Sent blast ACK to the network. ID 20, length 0
 Sent blast heartbeat to the network
^C==12538== 
==12538== Process terminating with default action of signal 2 (SIGINT)
==12538==    at 0x4A386C4: poll (poll.c:29)
==12538==    by 0x117353: main (simplemux.c:214)
==12538== 
==12538== HEAP SUMMARY:
==12538==     in use at exit: 24 bytes in 1 blocks
==12538==   total heap usage: 19 allocs, 18 frees, 41,892 bytes allocated
==12538== 
==12538== LEAK SUMMARY:
==12538==    definitely lost: 0 bytes in 0 blocks
==12538==    indirectly lost: 0 bytes in 0 blocks
==12538==      possibly lost: 0 bytes in 0 blocks
==12538==    still reachable: 24 bytes in 1 blocks
==12538==         suppressed: 0 bytes in 0 blocks
==12538== Rerun with --leak-check=full to see details of leaked memory
==12538== 
==12538== For counts of detected and suppressed errors, rerun with: -v
==12538== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
```