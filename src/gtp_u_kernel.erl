%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%% Copyright 2015, Travelping GmbH <info@travelping.com>

-module(gtp_u_kernel).

-behavior(gen_server).

%% API
-export([dev_create/4, create_pdp_context/6, update_pdp_context/6, delete_pdp_context/6]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-include_lib("kernel/include/file.hrl").
-include_lib("gen_netlink/include/netlink.hrl").

-record(state, {ns, gtp_nl, rt_nl, rt_nl_ns, gtp_genl_family, gtp_ifidx}).

%%====================================================================
%% API
%%====================================================================

-spec dev_create(Device     :: binary() | list(),
		 FD0        :: non_neg_integer(),
		 FD1u       :: non_neg_integer(),
		 Opts       :: [term()]) -> ok | {error, _}.

dev_create(Device, FD0, FD1u, Opts) ->
    gen_server:start_link(?MODULE, [Device, FD0, FD1u, Opts], []).

create_pdp_context(Server, Version, SGSN, MS, LocalTEI, RemoteTEI) ->
    gen_server:call(Server, {create_pdp_context, Version, SGSN, MS, LocalTEI, RemoteTEI}).

update_pdp_context(Server, Version, SGSN, MS, LocalTEI, RemoteTEI) ->
    gen_server:call(Server, {update_pdp_context, Version, SGSN, MS, LocalTEI, RemoteTEI}).

delete_pdp_context(Server, Version, SGSN, MS, LocalTEI, RemoteTEI) ->
    gen_server:call(Server, {delete_pdp_context, Version, SGSN, MS, LocalTEI, RemoteTEI}).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Device, FD0, FD1u, Opts]) ->
    VrfOpts = proplists:get_value(vrf, Opts, []),
    {ok, FDesc} = get_ns_fdesc(VrfOpts),
    NsFd = get_ns_fd(FDesc),
    {RtNl, RtNlNs} = netlink_sockets(VrfOpts),
    CreateGTPLinkInfo = [{fd0, FD0}, {fd1, FD1u}, {hashsize, 131072}],
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
    GtpIfIdx = configure_vrf(RtNlNs, Device, VrfOpts),

    {ok, GtpGenlFam} = get_family("gtp"),
    {ok, GtpNl} = gen_socket:socket(netlink, raw, ?NETLINK_GENERIC),
    ok = gen_socket:bind(GtpNl, netlink:sockaddr_nl(netlink, 0, 0)),

    {ok, #state{ns = NsFd, gtp_nl = GtpNl, rt_nl = RtNl, rt_nl_ns = RtNlNs, gtp_genl_family = GtpGenlFam, gtp_ifidx = GtpIfIdx}}.

handle_call({create_pdp_context, Version, SGSN, MS, LocalTID, RemoteTID},
	    _From, #state{ns = NsFd, gtp_nl = GtpNl, gtp_genl_family = GtpGenlFam,
			  gtp_ifidx = GtpIfIdx} = State) ->
    lager:debug("create_pdp_context: ~w, ~w, ~w, ~w, ~w", [Version, SGSN, MS, LocalTID, RemoteTID]),

    GtpReqAttrs = [{version,      Version},
		   {net_ns_fd,    NsFd},
		   {link,         GtpIfIdx},
		   {sgsn_address, SGSN},
		   {ms_address,   MS},
		   {i_tid,        LocalTID},                  %% TODO: GTPv0 TID and FLOW
		   {o_tid,        RemoteTID}],
    GtpReq = {new, 0, 0, GtpReqAttrs},
    Req = #netlink{type  = gtp,
		   flags = [?NLM_F_EXCL, ack, request],
		   seq   = erlang:unique_integer([positive]),
		   pid   = 0,
		   msg   = GtpReq},
    lager:debug("create_pdp_context: ~p", [Req]),
    Reply = nl_simple_request(GtpNl, GtpGenlFam, Req),

    {reply, Reply, State};

handle_call({update_pdp_context, Version, SGSN, MS, LocalTID, RemoteTID},
	    _From, #state{ns = NsFd, gtp_nl = GtpNl, gtp_genl_family = GtpGenlFam,
			  gtp_ifidx = GtpIfIdx} = State) ->
    lager:debug("update_pdp_context: ~w, ~w, ~w, ~w, ~w", [Version, SGSN, MS, LocalTID, RemoteTID]),

    GtpReqAttrs = [{version,      Version},
		   {net_ns_fd,    NsFd},
		   {link,         GtpIfIdx},
		   {sgsn_address, SGSN},
		   {ms_address,   MS},
		   {i_tid,        LocalTID},                  %% TODO: GTPv0 TID and FLOW
		   {o_tid,        RemoteTID}],
    GtpReq = {new, 0, 0, GtpReqAttrs},
    Req = #netlink{type  = gtp,
		   flags = [?NLM_F_REPLACE, ack, request],
		   seq   = erlang:unique_integer([positive]),
		   pid   = 0,
		   msg   = GtpReq},
    lager:debug("update_pdp_context: ~p", [Req]),
    Reply = nl_simple_request(GtpNl, GtpGenlFam, Req),

    {reply, Reply, State};

handle_call({delete_pdp_context, Version, SGSN, MS, LocalTID, _RemoteTID},
	    _From, #state{ns = NsFd, gtp_nl = GtpNl, gtp_genl_family = GtpGenlFam,
			  gtp_ifidx = GtpIfIdx} = State) ->
    lager:debug("delete_pdp_context: ~w, ~w, ~w, ~w, ~w", [Version, SGSN, MS, LocalTID, _RemoteTID]),

    GtpReqAttrs = [{version,      Version},
		   {net_ns_fd,    NsFd},
		   {link,         GtpIfIdx},
		   {sgsn_address, SGSN},
		   {ms_address,   MS},
		   {i_tid,        LocalTID}],                  %% TODO: GTPv0 TID and FLOW
    GtpReq = {delete, 0, 0, GtpReqAttrs},
    Req = #netlink{type  = gtp,
		   flags = [?NLM_F_EXCL, ack, request],
		   seq   = erlang:unique_integer([positive]),
		   pid   = 0,
		   msg   = GtpReq},
    lager:debug("delete_pdp_context: ~p", [Req]),
    Reply = nl_simple_request(GtpNl, GtpGenlFam, Req),

    {reply, Reply, State};

handle_call(Request, _From, State) ->
    lager:warning("handle_call: ~p", [lager:pr(Request, ?MODULE)]),
    {reply, ok, State}.

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

-define(SELF_NET_NS, "/proc/self/ns/net").
-define(SIOCGIFINDEX, 16#8933).

get_ns_fdesc(Opts) ->
    try
	{netns, NetNs} = lists:keyfind(netns, 1, Opts),
	{ok, _} = file:open(filename:join("/var/run/netns", NetNs), [raw, read])
    catch
	_:_ ->
	    {ok, _} = file:open(?SELF_NET_NS, [raw, read])
    end.

get_ns_fd(FDesc) ->
    lager:notice("FDesc: ~p~n", [FDesc]),
    case FDesc of
    #file_descriptor{module = prim_file} ->
        #file_descriptor{data = {_, NsFd}} = FDesc,
        NsFd;
    #file_descriptor{module = _} ->
        PrivFDesc = FDesc#file_descriptor.data,
        binary:decode_unsigned(prim_file:get_handle(PrivFDesc),little)
    end.

%% get_ifindex(Name, Opts) when is_list(Name) ->
%%     get_ifindex(iolist_to_binary(Name), Opts);
%% get_ifindex(Name, Opts) ->
%%     {ok, S} = raw_socket(local, dgram, default, Opts),
%%     {ok, <<_:16/binary, Index:32/native-integer, _/binary>>} = gen_socket:ioctl(S, ?SIOCGIFINDEX, <<Name/binary,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>),
%%     gen_socket:close(S),
%%     Index.

%% raw_socket(Family, Type, Protocol, Opts) ->
%%     case proplists:get_value(netns, Opts) of
%%         undefined ->
%%             gen_socket:raw_socket(Family, Type, Protocol);
%%         NetNs ->
%%             gen_socket:raw_socketat(NetNs, Family, Type, Protocol)
%%     end.

netlink_sockets(Opts) ->
    {ok, RtNl} = gen_socket:socket(netlink, raw, ?NETLINK_ROUTE),
    ok = gen_socket:bind(RtNl, netlink:sockaddr_nl(netlink, 0, -1)),

    RtNlNs =
	case proplists:get_value(netns, Opts) of
	    undefined ->
		RtNl;
	    NetNs ->
		{ok, RtNlNs1} = gen_socket:socketat(NetNs, netlink, raw, ?NETLINK_ROUTE),
		ok = gen_socket:bind(RtNlNs1, netlink:sockaddr_nl(netlink, 0, -1)),
		ok = netlink:setsockopt(RtNlNs1, sol_netlink, netlink_add_membership, rtnlgrp_link),
		RtNlNs1
	end,
    ok = netlink:setsockopt(RtNlNs, sol_netlink, netlink_add_membership, rtnlgrp_link),
    {RtNl, RtNlNs}.

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

wait_for_interface(Socket, Device) ->
    receive
	#rtnetlink{type = newlink, msg = {_, _, Index, _, _, Attrs}} ->
	    case lists:keyfind(ifname, 1, Attrs) of
		{_, Device} ->
		    {ok, Index};
		_Other ->
		    wait_for_interface(Socket, Device)
	    end
    after
	5000 ->
	    {error, timeout}
    end.

get_interface_rt_table(Socket, VRF) when is_list(VRF) ->
    Seq = erlang:unique_integer([positive]),
    Msg = {unspec, arphrd_netrom, 0, [], [], [{ifname, VRF}]},
    Req = #rtnetlink{type  = getlink,
		     flags = [request],
		     seq   = Seq,
		     pid   = 0,
		     msg   = Msg},
    case nl_simple_request(Socket, ?NETLINK_ROUTE, Req) of
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
get_interface_rt_table(_Socket, undefined) ->
    {undefined, main}.

set_vrf(Socket, IfIdx, VRF) when is_integer(VRF) ->
    Seq = erlang:unique_integer([positive]),
    Msg = {unspec, arphrd_netrom, IfIdx, [], [],[{master, VRF}]},
    Req = #rtnetlink{type  = newlink,
		     flags = [ack,request],
		     seq   = Seq,
		     pid   = 0,
		     msg   = Msg},
    nl_simple_request(Socket, ?NETLINK_ROUTE, Req);
set_vrf(_Socket, _IfIdx, _) ->
    ok.

add_route(Socket, IfIdx, Table, {{_,_,_,_} = IP, Len}) ->
    Seq = erlang:unique_integer([positive]),
    Msg = {inet, Len, 0, 0, Table, static, universe, unicast, [],
	   [{dst,IP}, {oif,IfIdx}]},
    Req = #rtnetlink{type  = newroute,
		     flags = [create,ack,request],
		     seq   = Seq,
		     pid   = 0,
		     msg   = Msg},
    case nl_simple_request(Socket, ?NETLINK_ROUTE, Req) of
	#rtnetlink{type = newroute} ->
	    ok;
	Other ->
	    Other
    end.

configure_vrf(RtNlNs, Device, VrfOpts) ->
    {ok, GtpIfIdx} = wait_for_interface(RtNlNs, Device),

    Routes = proplists:get_value(routes, VrfOpts, []),
    VRF = proplists:get_value(netdev, VrfOpts),

    {VrfIdx, VrfTable} = get_interface_rt_table(RtNlNs, VRF),
    ok = set_vrf(RtNlNs, GtpIfIdx, VrfIdx),
    lists:foreach(fun(R) -> ok = add_route(RtNlNs, GtpIfIdx, VrfTable, R) end, Routes),

    GtpIfIdx.

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
