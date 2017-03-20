%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%% Copyright 2017, Travelping GmbH <info@travelping.com>

-module(gtp_u_kmod_netns).

-compile({parse_transform, cut}).

-behavior(gen_server).

%% API
-export([start_link/1, create_vrf/2, destroy_vrf/2, enable_gtp_encap/3]).
-export([create_pdp_context/8, update_pdp_context/7, delete_pdp_context/7]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("kernel/include/file.hrl").
-include_lib("gen_netlink/include/netlink.hrl").

-record(state, {ns, gtp_nl, rt_nl, gtp_genl_family}).

%%====================================================================
%% API
%%====================================================================

start_link(NetNs) ->
    RegName = netns_reg_name(NetNs),
    gen_server:start_link({local, RegName}, ?MODULE, [NetNs], []).

create_vrf(NetNs, Opts) ->
    call(NetNs, {create_vrf, Opts}).

destroy_vrf(NetNs, GtpDev) ->
    case erlang:whereis(netns_reg_name(NetNs)) of
	Pid when is_pid(Pid) ->
	    gen_server:cast(Pid, {destroy_vrf, GtpDev});
	_ ->
	    ok
    end.

enable_gtp_encap(NetNs, Socket, Version) ->
    call(NetNs, {enable_gtp_encap, Socket, Version}).

create_pdp_context(NetNs, Version, SGSN, MS, GtpDevice, Socket, LocalTEI, RemoteTEI) ->
    lager:info("KMOD NetNs Create PDP Context Call ~p: ~p, ~p", [NetNs, GtpDevice, Socket]),
    call(NetNs, {create_pdp_context, Version, SGSN, MS, GtpDevice, Socket, LocalTEI, RemoteTEI}).

update_pdp_context(NetNs, Version, SGSN, MS, Socket, LocalTEI, RemoteTEI) ->
    call(NetNs, {update_pdp_context, Version, SGSN, MS, Socket, LocalTEI, RemoteTEI}).

delete_pdp_context(NetNs, Version, SGSN, MS, Socket, LocalTEI, RemoteTEI) ->
    call(NetNs, {delete_pdp_context, Version, SGSN, MS, Socket, LocalTEI, RemoteTEI}).

with_netns(NetNs, Fun) ->
    Server =
	case erlang:whereis(netns_reg_name(NetNs)) of
	    Pid when is_pid(Pid) ->
		Pid;
	    _ ->
		{ok, Pid} = gtp_u_kmod_netns_sup:new(NetNs),
		Pid
	end,
    Fun(Server).

call(NetNs, Opts) ->
    with_netns(NetNs, gen_server:call(_, Opts)).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([NetNs]) ->
    {ok, FDesc} = get_ns_fd(NetNs),
    #file_descriptor{module = prim_file,
		     data   = {_Port, NsFd}} = FDesc,

    RtNl = netlink_socket(NetNs),

    {ok, GtpGenlFam} = get_family("gtp"),
    {ok, GtpNl} = socket(NetNs, netlink, raw, ?NETLINK_GENERIC),
    ok = gen_socket:bind(GtpNl, netlink:sockaddr_nl(netlink, 0, 0)),

    {ok, #state{ns = NsFd, gtp_nl = GtpNl, rt_nl = RtNl, gtp_genl_family = GtpGenlFam}}.

handle_call({create_vrf, Opts}, _From, #state{ns = NsFd, rt_nl = RtNl} = State) ->
    HashSize = proplists:get_value(hashsize, Opts, 131072),
    Device = proplists:get_value(device, Opts),

    CreateGTPLinkInfo = [{hashsize, HashSize}],
    CreateGTPData = netlink:linkinfo_enc(inet, "gtp", CreateGTPLinkInfo),
    CreateGTPMsg = {inet,arphrd_none, 0, [up], [up],
		    [{net_ns_fd, NsFd},
		     {ifname,    Device},
		     {linkinfo,[{kind, "gtp"},
				{data, CreateGTPData}]}]},
    CreateGTPReq = #rtnetlink{type  = newlink,
			      flags = [create,excl,ack,request],
			      seq   = erlang:unique_integer([positive]),
			      pid   = 0,
			      msg   = CreateGTPMsg},
    lager:debug("CreateGTPReq: ~p", [CreateGTPReq]),

    ok = nl_simple_request(RtNl, ?NETLINK_ROUTE, CreateGTPReq),
    GtpDevice = configure_vrf(Device, Opts, State),
    {reply, {ok, GtpDevice}, State};

handle_call({enable_gtp_encap, Socket, Version}, _From, State) ->
    GtpReqAttrs = [{version, Version},
		   {fd,      Socket}],
    GtpReq = {enable_socket, 0, 0, GtpReqAttrs},
    Reply = gtp_request(GtpReq, ?NLM_F_EXCL, State),

    {reply, Reply, State};

handle_call({create_pdp_context, Version, SGSN, MS, GtpDevice, Socket, LocalTID, RemoteTID},
	    _From, #state{ns = NsFd} = State) ->
    lager:debug("create_pdp_context: ~w, ~w, ~w, ~w, ~w, ~w, ~w",
		[Version, SGSN, MS, GtpDevice, Socket, LocalTID, RemoteTID]),

    GtpReqAttrs = [{version,      Version},
		   {net_ns_fd,    NsFd},
		   {link,         GtpDevice},
		   nla_gsn_peer_address(SGSN),
		   {ms_address,   MS},
		   {i_tid,        LocalTID},                  %% TODO: GTPv0 TID and FLOW
		   {o_tid,        RemoteTID},
		   {fd,           Socket}],
    GtpReq = {new, 0, 0, GtpReqAttrs},
    Reply = gtp_request(GtpReq, ?NLM_F_EXCL, State),

    {reply, Reply, State};

handle_call({update_pdp_context, Version, SGSN, MS, Socket, LocalTID, RemoteTID},
	    _From, State) ->
    lager:debug("update_pdp_context: ~w, ~w, ~w, ~w, ~w",
		[Version, SGSN, MS, Socket, LocalTID, RemoteTID]),

    GtpReqAttrs = [{version,      Version},
		   nla_gsn_peer_address(SGSN),
		   {ms_address,   MS},
		   {i_tid,        LocalTID},                  %% TODO: GTPv0 TID and FLOW
		   {o_tid,        RemoteTID},
		   {fd,           Socket}],
    GtpReq = {new, 0, 0, GtpReqAttrs},
    Reply = gtp_request(GtpReq, ?NLM_F_REPLACE, State),

    {reply, Reply, State};

handle_call({delete_pdp_context, Version, SGSN, MS, Socket, LocalTID, _RemoteTID},
	    _From, State) ->
    lager:debug("delete_pdp_context: ~w, ~w, ~w, ~w, ~w, ~w", [Version, SGSN, MS, Socket, LocalTID, _RemoteTID]),

    GtpReqAttrs = [{version,      Version},
		   {i_tid,        LocalTID},
		   {fd,           Socket}],                  %% TODO: GTPv0 TID and FLOW
    GtpReq = {delete, 0, 0, GtpReqAttrs},
    Reply = gtp_request(GtpReq, ?NLM_F_EXCL, State),

    {reply, Reply, State};

handle_call(Request, _From, State) ->
    lager:warning("handle_call: ~p", [lager:pr(Request, ?MODULE)]),
    {reply, ok, State}.

handle_cast({destroy_vrf, GtpDev}, #state{rt_nl = RtNl} = State) ->
    DestroyGTPMsg = {inet,arphrd_none, GtpDev, [up], [up], []},
    DestroyGTPReq = #rtnetlink{type  = dellink,
			       flags = [destroy,excl,ack,request],
			       seq   = erlang:unique_integer([positive]),
			       pid   = 0,
			       msg   = DestroyGTPMsg},
    lager:debug("DestroyGTPReq: ~p", [DestroyGTPReq]),

    ok = nl_simple_request(RtNl, ?NETLINK_ROUTE, DestroyGTPReq),
    {noreply, State};
handle_cast(Msg, State) ->
    lager:debug("handle_cast: ~p", [lager:pr(Msg, ?MODULE)]),
    {noreply, State}.

handle_info(Info, State) ->
    lager:debug("handle_info: ~p", [lager:pr(Info, ?MODULE)]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%--------------------------------------------------------------------
%%% Internal functions
%%--------------------------------------------------------------------

netns_reg_name(Name) when is_atom(Name) ->
    BinName = iolist_to_binary(io_lib:format("netns_~s", [Name])),
    binary_to_atom(BinName, latin1).

-define(SELF_NET_NS, "/proc/self/ns/net").
-define(SIOCGIFINDEX, 16#8933).

get_ns_fd(NetNs) when is_list(NetNs) ->
    try
	{ok, _} = file:open(filename:join("/var/run/netns", NetNs), [raw, read])
    catch
	_:_ ->
	    {ok, _} = file:open(?SELF_NET_NS, [raw, read])
    end;
get_ns_fd(_NetNs) ->
    {ok, _} = file:open(?SELF_NET_NS, [raw, read]).

%% get_ifindex(Name, Opts) when is_list(Name) ->
%%     get_ifindex(iolist_to_binary(Name), Opts);
%% get_ifindex(Name, Opts) ->
%%     {ok, S} = raw_socket(local, dgram, default, Opts),
%%     {ok, <<_:16/binary, Index:32/native-integer, _/binary>>} = gen_socket:ioctl(S, ?SIOCGIFINDEX, <<Name/binary,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>),
%%     gen_socket:close(S),
%%     Index.

socket(NetNs, Family, Type, Protocol) when is_list(NetNs) ->
    gen_socket:socketat(NetNs, Family, Type, Protocol);
socket(_NetNs, Family, Type, Protocol) ->
    gen_socket:socket(Family, Type, Protocol).

netlink_socket(NetNs) ->
    {ok, S} = socket(NetNs, netlink, raw, ?NETLINK_ROUTE),
    ok = gen_socket:bind(S, netlink:sockaddr_nl(netlink, 0, -1)),
    ok = netlink:setsockopt(S, sol_netlink, netlink_add_membership, rtnlgrp_link),
    S.

get_family(Family) ->
    {ok, S} = gen_socket:socket(netlink, raw, ?NETLINK_GENERIC),

    Get = {getfamily, 1, 0, [{family_id, generic}, {family_name, Family}]},
    Seq = erlang:unique_integer([positive]),
    Req = #netlink{type  = ctrl,
		   flags = [ack,request],
		   seq   = Seq,
		   pid   = 0,
		   msg = Get},

    Return =
	case nl_simple_request(S, ?NETLINK_GENERIC, Req) of
	    #netlink{type = ctrl, seq = Seq, msg = {newfamily, _, _, Attrs}} ->
		{_, FamilyId} = lists:keyfind(family_id, 1, Attrs),
		{ok, FamilyId};
	    Other ->
		lager:error("genl family got ~p", [Other]),
		{error, unknown}
	end,
    gen_socket:close(S),
    Return.

wait_for_interface(Device) ->
    receive
	#rtnetlink{type = newlink, msg = {_, _, Index, _, _, Attrs}} ->
	    case lists:keyfind(ifname, 1, Attrs) of
		{_, Device} ->
		    {ok, Index};
		_Other ->
		    wait_for_interface(Device)
	    end
    after
	5000 ->
	    {error, timeout}
    end.

get_interface_rt_table(VRF, #state{rt_nl = RtNl}) when is_list(VRF) ->
    Seq = erlang:unique_integer([positive]),
    Msg = {unspec, arphrd_netrom, 0, [], [], [{ifname, VRF}]},
    Req = #rtnetlink{type  = getlink,
		     flags = [request],
		     seq   = Seq,
		     pid   = 0,
		     msg   = Msg},
    case nl_simple_request(RtNl, ?NETLINK_ROUTE, Req) of
	 #rtnetlink{type  = newlink, msg = {Family, _, IfIdx, _, _, Attrs}} ->
	    LinkInfo = proplists:get_value(linkinfo, Attrs, []),
	    Kind = proplists:get_value(kind, LinkInfo),
	    Data = proplists:get_value(data, LinkInfo),
	    case netlink:linkinfo_dec(Family, Kind, Data) of
		LI when is_list(LI) ->
		    {IfIdx, proplists:get_value(vrf_table, LI, main)};
		_ ->
		    lager:error("invalid VRF definition ~p", [VRF]),
		    {undefined, main}
	    end;
	_ ->
	    lager:error("invalid VRF definition ~p", [VRF]),
	    {undefined, main}
    end;
get_interface_rt_table(undefined, _State) ->
    {undefined, main}.

set_vrf(IfIdx, VRF, #state{rt_nl = RtNl}) when is_integer(VRF) ->
    Seq = erlang:unique_integer([positive]),
    Msg = {unspec, arphrd_netrom, IfIdx, [], [],[{master, VRF}]},
    Req = #rtnetlink{type  = newlink,
		     flags = [ack,request],
		     seq   = Seq,
		     pid   = 0,
		     msg   = Msg},
    nl_simple_request(RtNl, ?NETLINK_ROUTE, Req);
set_vrf(_IfIdx, _, _State) ->
    ok.

add_route(IfIdx, Table, {{_,_,_,_} = IP, Len}, #state{rt_nl = RtNl}) ->
    Seq = erlang:unique_integer([positive]),
    Msg = {inet, Len, 0, 0, Table, static, universe, unicast, [],
	   [{dst,IP}, {oif,IfIdx}]},
    Req = #rtnetlink{type  = newroute,
		     flags = [create,ack,request],
		     seq   = Seq,
		     pid   = 0,
		     msg   = Msg},
    case nl_simple_request(RtNl, ?NETLINK_ROUTE, Req) of
	#rtnetlink{type = newroute} ->
	    ok;
	Other ->
	    Other
    end.

configure_vrf(Device, Opts, State) ->
    {ok, GtpIfIdx} = wait_for_interface(Device),

    Routes = proplists:get_value(routes, Opts, []),
    VRF = proplists:get_value(netdev, Opts),

    {VrfIdx, VrfTable} = get_interface_rt_table(VRF, State),
    ok = set_vrf(GtpIfIdx, VrfIdx, State),
    lists:foreach(fun(R) -> ok = add_route(GtpIfIdx, VrfTable, R, State) end, Routes),

    GtpIfIdx.

gtp_request(Request, Flag, #state{gtp_nl = GtpNl, gtp_genl_family = GtpGenlFam}) ->
    Req = #netlink{type  = gtp,
		   flags = [Flag, ack, request],
		   seq   = erlang:unique_integer([positive]),
		   pid   = 0,
		   msg   = Request},
    lager:debug("GTP request: ~p", [Req]),
    nl_simple_request(GtpNl, GtpGenlFam, Req).

nl_simple_response(error, {0, _}, _Response) ->
    ok;
nl_simple_response(error, {Code, _}, _Response) ->
    {error, Code};
nl_simple_response(_, _, Response) ->
    Response.

nl_simple_response(_Seq, []) ->
    continue;
nl_simple_response(Seq, [Response = #rtnetlink{type = Type, seq = Seq, msg = Msg} | Next ]) ->
    nl_simple_response(-1, Next),
    nl_simple_response(Type, Msg, Response);
nl_simple_response(Seq, [Response = #netlink{type = Type, seq = Seq, msg = Msg} | Next]) ->
    nl_simple_response(-1, Next),
    nl_simple_response(Type, Msg, Response);
nl_simple_response(Seq, [Other | Next]) ->
    self() ! Other,
    nl_simple_response(Seq, Next).

wait_for_response(Socket, Protocol, Seq, Cb) ->
    ok = gen_socket:input_event(Socket, true),
    receive
	{Socket, input_ready} ->
	    Response = process_answer(Socket, Protocol, Cb, []),
	    case nl_simple_response(Seq, Response) of
		continue ->
		    wait_for_response(Socket, Protocol, Seq, Cb);
		Other ->
		    Other
	    end;

	#rtnetlink{type = Type, seq = Seq, msg = Msg} = Response ->
	    nl_simple_response(Type, Msg, Response);

	#netlink{type = Type, seq = Seq, msg = Msg} = Response ->
	    nl_simple_response(Type, Msg, Response)
    after
	1000 ->
	    {error, timeout}
    end.

nl_simple_request(Socket, Protocol, #rtnetlink{seq = Seq} = Req)  ->
    do_request(Socket, Protocol, Req),
    wait_for_response(Socket, Protocol, Seq, fun nl/2);
nl_simple_request(Socket, Protocol, #netlink{seq = Seq} = Req)  ->
    do_request(Socket, Protocol, Req),
    wait_for_response(Socket, Protocol, Seq, fun nl/2).

do_request(Socket, Protocol, Req) ->
    BinReq = netlink:nl_enc(Protocol, Req),
    gen_socket:send(Socket, BinReq).

process_answer(Socket, Protocol, Cb, CbState0) ->
    case gen_socket:recv(Socket, 16 * 1024 * 1024) of
        {ok, Data} ->
            Msg = netlink:nl_dec(Protocol, Data),
            case process_nl(false, Msg, Cb, CbState0) of
                {continue, CbState1} ->
                    process_answer(Socket, Protocol, Cb, CbState1);
                CbState1 ->
                    CbState1
            end;
        Other ->
            io:format("Other: ~p~n", [Other]),
            Other
    end.

process_nl(true, [], _Cb, CbState) ->
    {continue, CbState};
process_nl(_, [], _Cb, CbState) ->
    CbState;
process_nl(_Multi, [#netlink{type = done}], _Cb, CbState) ->
    CbState;
process_nl(_Multi, [Head|Rest], Cb, CbState0) ->
    CbState1 = Cb(Head, CbState0),
    Flags = element(3, Head),
    process_nl(lists:member(multi, Flags), Rest, Cb, CbState1).

nl(Msg, Acc) ->
    [Msg|Acc].

nla_gsn_peer_address({_,_,_,_,_,_,_,_} = IP) ->
    {sgsn_address6, IP};
nla_gsn_peer_address({_,_,_,_} = IP) ->
    {sgsn_address, IP}.
