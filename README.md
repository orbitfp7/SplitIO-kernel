This is part of the Resource Consolidation Layer (RCL) of the ORBIT project. For more information please visit the our website: http://www.orbitproject.eu

Introduction
============

I/O consolidation is a new paravirtual I/O model providing a centralized, scalable facility for handling I/O services. It does so by decoupling I/O from computation on the machines hosting the VMs, and shifts the processing of the I/O to a dedicated server (I/O hypervisor). Firewall, DPI (deep packet inspection) and block-level encryption are examples of such I/O services. These I/O services can consume a lot of CPU resources, thus, consolidating them in a dedicated server increases CPU utilization and accommodates changing load conditions where demand from different hosts fluctuates. 
				
Setup
=====

Split I/O assumes layer 2 (Ethernet) connectivity between the I/O hypervisor and the virtual machines. A virtual machine can utilize a direct assign network device in order to communicate to the I/O hypervisor for best performance. However, it is not mandatory. The guest can use any other virtual network device, provided that it can communicate over layer 2 with the I/O hypervisor. Additionally, the guest drivers are agnostic to the underlying hypervisor (e.g., ESXi, Xen), even bare-metal.

Split I/O was originally implemented using a proprietary lightweight protocol (directly over layer 2), not TCP, which resulted in an incompatibility for integration. To address this issue, we decided that the best course of action is to mimic a legitimate TCP/IP connection. This includes:
							
0. 3-way handshake
0. sequence and acknowledge number handling for each packet
0. populating TCP and IP header with valid data such as IP:PORT for the source as well as the destination.

Although it looks like a real TCP stream, it doesn't incur the overhead associated with TCP/IP. The TCP stack is not being used on either end, the I/O hypervisor and the VM. 

Installation
============

Our proof-of-concept is based on Linux kernel 3.10. Split I/O drivers are based on vhost and virtio drivers. One source tree for both the I/O hypervisor and the I/O guests. 

Linux
-----

- Download the code from the following repository: https://github.com/orbitfp7/SplitIO-kernel
- Create a kernel config file that matches your test machine’s configuration. If you already have a config file, you can use it (perhaps one provided by the distro). If not, you can create a default one that should work by running ‘make localmodconfig’.
- Modify the config file to ensure all of the following configuration options are enabled (for the I/O hypervisor):

```
CONFIG_MACVLAN=m
CONFIG_MACVTAP=m
CONFIG_TUN=m
CONFIG_BRIDGE=m
CONFIG_STP=m
CONFIG_LLC=m
```

Note: Split I/O drivers are built automatically as kernel modules and can be found here: `<kernel_source>/drivers/vrio/`

- Build the kernel as usual (make, make modules_install, make install)

Run
===

Please download the scripts from the following link: https://github.com/orbitfp7/SplitIO-scripts.

You must install the drivers in both the I/O hypervisor and the guest before instantiating any virtual devices. To install the driver use the following scripts:

Loading the modules
-------------------

To install the back-end drivers execute the following script on the I/O hypervisor:
```
<scripts>/examples/install-backend-drivers.sh
```
To install the front-end drivers execute the following script on all the guests:
```
<scripts>/examples/install-frontend-drivers.sh
```

Exposing virtual devices
------------------------

Run the following scripts from the I/O hypervisor machine in order to expose virtual devices to guests. You must edit the scripts and modify them based on your setup.

To instantiate a virtual network device use the following script:
```
<scripts>/examples/create-remote-virtual-nic.sh
```
Removing virtual network device is done through the following script:
```
<scripts>/examples/iohyp_remove_net_device.sh
```
Please use `create-remote-virtual-blk.sh` and `iohyp_remove_blk_device.sh` scripts to create and remove virtual block devices, respectively.

Publications
============

Comprehensive measurement can be found here (ASPLOS’16): http://dl.acm.org/citation.cfm?id=2872378 



