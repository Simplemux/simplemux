Running Simplemux in a MikroTik RB2011UiAS-IN router
----------------------------------------------------
(15/04/2016)

MikroTik RouterOS 6.30.2 (c) 1999-2015 http://www.mikrotik.com/
Version of the RouterOS
```
[admin@MikroTik] > export
# jan/02/1970 00:37:08 by RouterOS 6.30.2
# software id = 1QGM-D3VP
#
```

# Internal structure of the router

See https://www.cloudrouterswitches.com/RB2011UiAS-IN.asp

<img src="images/mikrotik_structure.png" alt="Internal structure of a MikroTik router" width="600"/>

## Create a metarouter (a Virtual Machine running in the router)

http://wiki.mikrotik.com/wiki/Manual:Metarouter

They are Virtual Machines (VMs) that can run OSes as e.g. OpenWrt. You can create them with the web interface or with the command interface of the MikroTik router.

You can download an OpenWrt VM from here:
https://wiki.mikrotik.com/Manual:Metarouter

Then, upload the `.tgz` file to the MikroTik router. You can use WinSCP or any other remote file manager. You can also use the _Files_ option in the web interface of the MikroTik router, to select a file of your PC and to upload it.

## Start the Virtual Machine

Use the web or the command interface:

```
[admin@MikroTik] > metarouter
[admin@MikroTik] /metarouter> add name=mr0 memory-size=32 disk-size=32000 disabled=no
[admin@MikroTik] /metarouter> print
Flags: X - disabled
# NAME    MEMORY-SIZE      DISK-SIZE    USED-DISK   STATE
0 mr0     32MiB            32000kiB     5kiB        running
[admin@MikroTik] /metarouter>
```

Then, using the “console” button of the web, you can open a console of the OpenWrt VM:

<img src="images/mikrotik_console.png" alt="OpenWRT VM console in the Mikrotik router" width="600"/>

## Adding an Eth device to the OpenWrt VM

https://forum.mikrotik.com/viewtopic.php?t=32187&start=250

This command binds the interface `eth2` of the MikroTik router as the `eth0` interface of the `mr2` VM (an OpenWrt machine in this case):

```
[admin@MikroTik] /metarouter> interface
[admin@MikroTik] /metarouter interface> add static-interface=ether2-master-local virtual-machine=mr2 vm-mac-address=02:97:24:54:0D:20
```

Now, if you connect a wire to the `eth2` port of the MikroTik router, you will be able to access the VM via SSH.

Go to the VM (using the console you can open from the web interface of the MikroTik router) and add an IP address to the `eth0` interface:

```
root@metarouter:~# ifconfig eth0 192.168.1.2
```

## Installing openvpn in the OpenWrt vm

You need to install these packages for creating a tun device in the OpenWrt VM.

Downloaded from: https://openwrt.wk.cz/attitude_adjustment/mr-mips/packages/

```
# opkg install /root/kmod-tun_3.3.8-1_mr-mips.ipk
# opkg install /root/liblzo_2.06-1_mr-mips.ipk
# opkg install /root/zlib_1.2.7-1_mr-mips.ipk
# opkg install /root/libopenssl_1.0.1e-1_mr-mips.ipk
# opkg install /root/openvpn_2.2.2-2_mr-mips.ipk
```


## Running Simplemux in the OpenWrt vm
Create a tun interface:

```
openvpn --mktun --dev tun0 --user root
```

You can get the Simplemux executable, compiled for OpenWrt here: https://github.com/TCM-TF/simplemux/blob/master/simplemux-mips

Copy the simplemux file and run it normally in the vm:

```
./simplemux-mips -i tun0 -e eth0 -c 192.168.1.17 -M T
```

<img src="images/mikrotik_simplemux.png" alt="Simplemux running in the Mikrotik router" width="600"/>