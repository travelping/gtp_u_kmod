gtp_u_kmod - GTPv1-U Erlang interface process for Kernel Datapath
=================================================================
[![Build Status][travis badge]][travis]
[![Erlang Versions][erlang version badge]][travis]

This is a interface to the Linux kernel GTPv1-U (3GPP TS 29.281) datapath element for the erGW GGSN/PGW project implemented in pure Erlang.

BUILDING
--------

Using rebar:

    # rebar3 compile

RUNNING
-------

Requirements:

* Erlang 20.0
* Linux 4.6 with gtp kernel module

GTP-u-KMod is the kernel based GTP-U data path instance for [erGW](https://github.com/travelping/ergw)

Sample config for use with erGW with two VRF-Lite instances (grx and upstream):

```
[{gtp_u_kmod, [
	{sockets, [{grx, [{ip, {192,0,2,16}},
			   {netdev, "grx"},
			   freebind,
			   {vrf, [{routes, [{{10, 180, 0, 0}, 16}]},
					  {netdev, "upstream"}
					 ]}
			  ]}
	]}
]}].
```

### Linux Kernel VRF-Lite

The Linux Kernel concept of VRF's should not be confused with the configuration of the GTP VRF.
A GTP VRF can be mapped onto a Linux VRF-Lite instance or alternativly into a Linux network namespace.

Both the GTP socket and the GTP network device can be bound to VRF instances with the netdev option.
For GTP sockets the binding is optional, but for the network devices the binding is mandatory.

### GTP VRF

A GTP VRF describes a virtual Linux network interface that serves a give client IP range. All traffic is routed into that interface and matches a GTP tunnel is GTP encapsulated and forwarded to a S-GW/SGSN.


<!-- Badges -->
[travis]: https://travis-ci.org/travelping/gtp_u_kmod
[travis badge]: https://img.shields.io/travis/travelping/gtp_u_kmod/master.svg?style=flat-square
[erlang version badge]: https://img.shields.io/badge/erlang-R20.0%20to%2020.1-blue.svg?style=flat-square
