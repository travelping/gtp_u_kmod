gtp_u_kmod - GTPv1-U Erlang interface process for Kernel Datapath
=================================================================
[![Build Status](https://travis-ci.org/travelping/gtp_u_kmod.svg?branch=master)](https://travis-ci.org/travelping/gtp_u_kmod)

This is a interface to the Linux kernel GTPv1-U (3GPP TS 29.281) datapath element for the erGW GGSN/PGW project implemented in pure Erlang.

BUILDING
--------

Using tetrapak:

    # tetrapak build check

Using rebar:

    # rebar get-deps
    # rebar compile

RUNNING
-------

Requirements:

* Erlang 19.0
* Linux 4.6 with gtp kernel module

GTP-u-KMod is the kernel based GTP-U data path instance for [erGW](https://github.com/travelping/ergw)

Sample config for use with erGW:

```
[{gtp_u_kmod, [
	{sockets, [{grx, [{ip, {192,0,2,16}},
			  {netdev, "grx"},
			  freebind,
			  {routes, [{{10, 180, 0, 0}, 16}]}
			 ]}
	]}
]}].
```