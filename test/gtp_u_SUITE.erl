%% Copyright 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_SUITE).

-compile(export_all).
-compile(nowarn_export_all).

-include_lib("common_test/include/ct.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include("../include/gtp_u_kmod.hrl").

-define(TIMEOUT, 2000).
-define(MS_IP, {10,180,0,10}).
-define(LOCALHOST, {127,0,0,1}).
-define(CLIENT_IP, {127,127,127,127}).
-define(CLIENT_IP_BIN, <<127,127,127,127>>).
-define(TEST_GSN, ?LOCALHOST).
-define(GTP_INTF, 'grx').
-define(SGI_INTF, 'lo CURRENTLY UNUSED').
-define(TEST_SRV, {127,0,200,1}).


-define(PROXY_GSN, {127,0,100,1}).
-define(FINAL_GSN, {127,0,200,1}).

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
	 (Expected@@@, Actual@@@) ->
	     ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
		    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
	     false
     end)(Expected, Actual) orelse error(badmatch)).

-define(match(Guard, Expr),
	((fun () ->
		  case (Expr) of
		      Guard -> ok;
		      V -> ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~s~n",
				   [?FILE, ?LINE, ??Expr, ??Guard,
				    pretty_print(V)]),
			    error(badmatch)
		  end
	  end)())).

-define('Tunnel Endpoint Identifier Data I',	{tunnel_endpoint_identifier_data_i, 0}).

%%%===================================================================
%%% API
%%%===================================================================

-define(TEST_CONFIG,
	[
	 {lager, [{colored, true},
		  {error_logger_redirect, false},
		  %% force lager into async logging, otherwise
		  %% the test will timeout randomly
		  {async_threshold, undefined},
		  {handlers, [{lager_console_backend, [{level, info}]}]}
		 ]},

	 {gtp_u_kmod, [{sockets,
		       [{grx, [{ip, ?TEST_GSN},
			       {vrf, [{routes, [{{10, 180, 0, 0}, 16}]}]}
			      ]}
		       ]}
		      ]}
	]).

init_per_suite(Config0) ->
    Config = init_ets(Config0),
    [application:load(App) || App <- [lager, gtp_u_kmod]],
    meck_init(Config),
    load_config(?TEST_CONFIG),
    {ok, _} = application:ensure_all_started(gtp_u_kmod),
    lager_common_test_backend:bounce(debug),

    os:cmd("/sbin/ip link set gtp0 mtu 1500"),
    os:cmd("/sbin/ip link set gtp0 up"),
    ct:pal("ip link:~n~s", [os:cmd("/sbin/ip link")]),
    ct:pal("ip addr:~n~s", [os:cmd("/sbin/ip addr")]),
    ct:pal("ip route:~n~s", [os:cmd("/sbin/ip route")]),
    ct:pal("sockets:~n~s", [os:cmd("/bin/ss -aun")]),
    Config.

end_per_suite(Config) ->
    meck_unload(Config),
    ?config(table_owner, Config) ! stop,
    [application:stop(App) || App <- [lager, gtp_u_kmod]],
    ok.

init_per_testcase(forward_data, Config) ->
    meck_reset(Config),
    {ok, IfList} = inet:getifaddrs(),
    case getfirst(fun({"lo", _IfOpts}) ->
			  false;
		     ({_IfName, IfOpts}) ->
			  Flags = proplists:get_value(flags, IfOpts, []),
			  {lists:sort(Flags) ==
			      lists:sort([up,broadcast,running,multicast]),
			   proplists:get_value(addr, IfOpts)}
		  end,
		  IfList) of
	undefined ->
	    {skip, "no local interface for traffic test"};
	IfAddr ->
	    [{ifaddr, IfAddr} | Config]
    end;
init_per_testcase(_, Config) ->
    meck_reset(Config),
    Config.

end_per_testcase(_, Config) ->
    Config.

suite() ->
    [{timetrap,{seconds,30}}].

all() ->
    [
     invalid_gtp_pdu,
     invalid_teid,
     echo_request,
     bind,
     clear,
     session_establishment_request,
     session_establishment_request_clear,
     session_deletion_request,
     session_modification_request,
     forward_data,
     error_indication
    ].

%%%===================================================================
%%% Init/End helper
%%%===================================================================

ets_owner() ->
    receive
	stop ->
	    exit(normal);
	_ ->
	    ets_owner()
    end.

init_ets(Config) ->
    Pid = spawn(fun ets_owner/0),
    TabId = ets:new(?MODULE, [set, public, named_table, {heir, Pid, []}]),
    ets:insert(TabId, [{seq_no, 1},
		       {restart_counter, 1},
		       {teid, 1}]),
    [{table, TabId}, {table_owner, Pid} | Config].

load_config(AppCfg) ->
    lists:foreach(fun({App, Settings}) ->
			  ct:pal("App: ~p, S: ~p", [App, Settings]),
			  lists:foreach(fun({K,V}) ->
						ct:pal("App: ~p, K: ~p, V: ~p", [App, K, V]),
						application:set_env(App, K, V)
					end, Settings)
		  end, AppCfg),
    ok.

%%%===================================================================
%%% Meck functions for fake the GTP sockets
%%%===================================================================

meck_init(_Config) ->
    ok = meck:new(gtp_u_kmod, [passthrough, no_link]),
    ok = meck:new(gtp_u_kmod_port, [passthrough, no_link]),
    ok = meck:new(gtp_u_kernel, [passthrough, no_link]).

meck_reset(_Config) ->
    meck:reset(gtp_u_kmod),
    meck:reset(gtp_u_kmod_port),
    meck:reset(gtp_u_kernel).

meck_unload(_Config) ->
    meck:unload(gtp_u_kmod),
    meck:unload(gtp_u_kmod_port),
    meck:unload(gtp_u_kernel).

meck_validate(_Config) ->
    ?equal(true, meck:validate(gtp_u_kmod)),
    ?equal(true, meck:validate(gtp_u_kmod_port)),
    ?equal(true, meck:validate(gtp_u_kernel)).

%%%===================================================================
%%% Tests
%%%===================================================================

%%--------------------------------------------------------------------
invalid_gtp_pdu() ->
    [{doc, "Test that an invalid PDU is silently ignored"
      " and that the GTP socket is not crashing"}].
invalid_gtp_pdu(Config) ->
    S = make_gtp_socket(Config),
    gen_udp:send(S, ?TEST_GSN, ?GTP1u_PORT, <<"TESTDATA">>),

    ?equal({error,timeout}, gen_udp:recv(S, 4096, ?TIMEOUT)),

    ?match(1, meck:num_calls(gtp_u_kmod_port, handle_info, [{'_',input_ready}, '_'])),
    meck_validate(Config),
    ok.

invalid_teid() ->
    [{doc, "Test that an PDU with an unknown TEID is silently ignored"
      " and that the GTP socket is not crashing"}].
invalid_teid(Config) ->
    S = make_gtp_socket(Config, ?CLIENT_IP, 0),

    TEID = get_next_teid(),
    Msg =  #gtp{version = v1, type = g_pdu, tei = TEID, ie = <<"TESTDATA">>},
    send_pdu(S, Msg),

    %% Note: setting the Sequence number flag (S) is required for
    %%       Error Indications, that meant the seq_no fields will
    %%       contain a decoded integer value
    ?match(#gtp{version = v1, type = error_indication,
		tei = 0, seq_no = SeqNo,
		ie = #{{gsn_address,0} :=
			   #gsn_address{address = ?CLIENT_IP_BIN},
		       ?'Tunnel Endpoint Identifier Data I' :=
			   #tunnel_endpoint_identifier_data_i{tei = TEID}}}
	     when is_integer(SeqNo),
	   recv_pdu(S, ?TIMEOUT)),

    meck_validate(Config),
    ok.

echo_request() ->
    [{doc, "Test that a Echo Request is answered properly"}].
echo_request(Config) ->
    S = make_gtp_socket(Config),

    SeqNo = get_next_seq_no(),
    ReqIEs = [#recovery{restart_counter = 0}],
    Msg = #gtp{version = v1, type = echo_request, tei = 0,
	       seq_no = SeqNo, ie = ReqIEs},

    ?match(#gtp{version = v1, type = echo_response, tei = 0, seq_no = SeqNo},
	   send_recv_pdu(S, Msg)),

    meck_validate(Config),
    ok.

bind() ->
    [{doc, "Test GTP-C to DP bind call"}].
bind(Config) ->
    ?match({ok, _, ?TEST_GSN}, gen_server:call('gtp-u', {bind, grx})),
    ?match({reply, {error, not_found}}, gen_server:call('gtp-u', {bind, 'invalid'})),

    meck_validate(Config),
    ok.

clear() ->
    [{doc, "Test GTP-C to DP clear call"}].
clear(Config) ->
    {ok, Pid, _} = gen_server:call('gtp-u', {bind, grx}),
    ?equal(ok, gen_server:call(Pid, clear)),

    meck_validate(Config),
    ok.

session_establishment_request() ->
    [{doc, "CP to DP Session Establishment Request"}].
session_establishment_request(Config) ->
    SEID = get_next_teid(),
    GtpIntf = ?GTP_INTF,
    TEI = get_next_teid(),
    PeerIP = ?CLIENT_IP,
    PeerTEI = get_next_teid(),
    SgiIntf = ?SGI_INTF,
    MSv4 = ?MS_IP,

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, GtpIntf}),
    ok = gen_server:call(Pid, clear),

    Request = make_sgi_session(SEID, GtpIntf,TEI, PeerIP, PeerTEI, SgiIntf, MSv4),

    ?match(ok, gen_server:call(Pid, Request)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI,  PeerIP,  PeerTEI, SgiIntf, MSv4),

    ok = gen_server:call(Pid, clear),

    meck_validate(Config),
    ok.

session_establishment_request_clear() ->
    [{doc, "DP clear removes all existing forwarders"}].
session_establishment_request_clear(Config) ->
    SEID = get_next_teid(),
    GtpIntf = ?GTP_INTF,
    TEI = get_next_teid(),
    PeerIP = ?CLIENT_IP,
    PeerTEI = get_next_teid(),
    SgiIntf = ?SGI_INTF,
    MSv4 = ?MS_IP,

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, GtpIntf}),
    ok = gen_server:call(Pid, clear),

    Request = make_sgi_session(SEID, GtpIntf,TEI, PeerIP, PeerTEI, SgiIntf, MSv4),

    ?match(ok, gen_server:call(Pid, Request)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI,  PeerIP,  PeerTEI, SgiIntf, MSv4),

    ok = gen_server:call(Pid, clear),

    ?equal([], gtp_u_kmod_port:all(Pid)),

    meck_validate(Config),
    ok.

session_deletion_request() ->
    [{doc, "CP to DP Session Deletion Request"}].
session_deletion_request(Config) ->
    SEID = get_next_teid(),
    InvalidSEID = get_next_teid(),
    GtpIntf = ?GTP_INTF,
    TEI = get_next_teid(),
    PeerIP = ?CLIENT_IP,
    PeerTEI = get_next_teid(),
    SgiIntf = ?SGI_INTF,
    MSv4 = ?MS_IP,

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, GtpIntf}),
    ok = gen_server:call(Pid, clear),

    Request1 = make_sgi_session(SEID, GtpIntf,TEI, PeerIP, PeerTEI, SgiIntf, MSv4),
    Request2 = {InvalidSEID, session_deletion_request, #{}},
    Request3 = {SEID, session_deletion_request, #{}},

    ?match(ok, gen_server:call(Pid, Request1)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI,  PeerIP,  PeerTEI, SgiIntf, MSv4),

    ?match({error,not_found}, gen_server:call(Pid, Request2)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI,  PeerIP,  PeerTEI, SgiIntf, MSv4),

    ?equal(ok, gen_server:call(Pid, Request3)),

    ?equal([], gtp_u_kmod_port:all(Pid)),

    meck_validate(Config),
    ok.

session_modification_request() ->
    [{doc, "CP to DP Session Modification Request"}].
session_modification_request(Config) ->
    SEID = get_next_teid(),
    InvalidSEID = get_next_teid(),
    GtpIntf = ?GTP_INTF,
    TEI = get_next_teid(),
    PeerIP = ?CLIENT_IP,
    PeerTEI = get_next_teid(),
    SgiIntf = ?SGI_INTF,
    MSv4 = ?MS_IP,

    UpdTEI = get_next_teid(),
    UpdPeerIP = ?CLIENT_IP,
    UpdPeerTEI = get_next_teid(),

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, GtpIntf}),
    ok = gen_server:call(Pid, clear),

    S = make_gtp_socket(Config),

    Request1 = make_sgi_session(SEID, GtpIntf,TEI, PeerIP, PeerTEI, SgiIntf, MSv4),

    ?match(ok, gen_server:call(Pid, Request1)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI,  PeerIP,  PeerTEI, SgiIntf, MSv4),

    Request2 = make_update_far(InvalidSEID, GtpIntf,  UpdPeerIP, UpdPeerTEI),

    ?match({error,not_found}, gen_server:call(Pid, Request2)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI,  PeerIP,  PeerTEI, SgiIntf, MSv4),

    Request3 = make_update_far(SEID, GtpIntf, UpdPeerIP, UpdPeerTEI),

    ?match(ok, gen_server:call(Pid, Request3)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI, UpdPeerIP, UpdPeerTEI, SgiIntf, MSv4),

    Request4 = make_update_pdr(SEID, GtpIntf, UpdTEI),

    %% changing the local TEI or the MS IP is not supported by the kernel DP
    ?match({error,_}, gen_server:call(Pid, Request4)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI, UpdPeerIP, UpdPeerTEI, SgiIntf, MSv4),

    %% make sure we did not get an End Marker
    ?equal({error,timeout}, gen_udp:recv(S, 4096, ?TIMEOUT)),

    Request5 = make_update_far(SEID, GtpIntf, PeerIP, PeerTEI, true),

    ?match(ok, gen_server:call(Pid, Request5)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI, PeerIP, PeerTEI, SgiIntf, MSv4),

    %% make sure we DID get an End Marker
    ?match(#gtp{type = end_marker, tei = UpdLeftPeerTEI}, recv_pdu(S, ?TIMEOUT)),

    Request6 = {SEID, session_deletion_request, #{}},
    ?equal(ok, gen_server:call(Pid, Request6)),

    ?equal([], gtp_u_kmod_port:all(Pid)),

    meck_validate(Config),
    ok.

forward_data() ->
    [{doc, "Test forwarding data works"}].
forward_data(Config) ->
    SEID = get_next_teid(),
    GtpIntf = ?GTP_INTF,
    TEI = get_next_teid(),
    PeerIP = ?CLIENT_IP,
    PeerTEI = get_next_teid(),
    SgiIntf = ?SGI_INTF,
    MSv4 = ?MS_IP,

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, GtpIntf}),
    ok = gen_server:call(Pid, clear),

    Request1 = make_sgi_session(SEID, GtpIntf,TEI, PeerIP, PeerTEI, SgiIntf, MSv4),
    Request2 = {SEID, session_deletion_request, #{}},

    ?match(ok, gen_server:call(Pid, Request1)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI,  PeerIP,  PeerTEI, SgiIntf, MSv4),

    {ok, EchoPid, IP, Port} = proc_lib:start_link(?MODULE, echo_server,
						  [Config, self()]),

    S = make_gtp_socket(Config),
    UDP = make_udp(ip2bin(MSv4), ip2bin(IP), Port, Port, <<"TESTDATA">>),
    Msg = #gtp{version = v1, type = g_pdu, tei = TEI, ie = UDP},
    ?match(#gtp{type = g_pdu, tei = PeerTEI}, send_recv_pdu(S, Msg)),

    receive
	{EchoPid, done} -> ok
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    ?equal(ok, gen_server:call(Pid, Request2)),

    ?equal([], gtp_u_kmod_port:all(Pid)),

    meck_validate(Config),
    ok.

error_indication() ->
    [{doc, "Test Error Indication"}].
error_indication(Config) ->
    SEID = get_next_teid(),
    GtpIntf = ?GTP_INTF,
    TEI = get_next_teid(),
    PeerIP = ?CLIENT_IP,
    PeerTEI = get_next_teid(),
    SgiIntf = ?SGI_INTF,
    MSv4 = ?MS_IP,

    {ok, Pid, ?TEST_GSN} = gen_server:call('gtp-u', {bind, GtpIntf}),
    ok = gen_server:call(Pid, clear),

    Request1 = make_sgi_session(SEID, GtpIntf, TEI, PeerIP, PeerTEI, SgiIntf, MSv4),

    ?match(ok, gen_server:call(Pid, Request1)),
    validate_tunnel(Pid, SEID, GtpIntf, TEI, PeerIP, PeerTEI, SgiIntf, MSv4),

    S = make_gtp_socket(Config),

    MsgIE = [#tunnel_endpoint_identifier_data_i{tei = PeerTEI},
	     #gsn_address{address = ip2bin(PeerIP)}],
    Msg = #gtp{version = v1, type = error_indication, tei = 0,
		seq_no = undefined, ie = MsgIE},
    send_pdu(S, Msg),

    receive
	{SEID, session_report_request, IEs2} ->
	    ?match(#{report_type := [error_indication_report],
		     error_indication_report :=
			 [#{remote_f_teid :=
				#f_teid{ipv4 = ?CLIENT_IP, teid = PeerTEI}
			   }]
		    }, IEs2)
    after ?TIMEOUT ->
	    ct:fail(timeout)
    end,

    ok = gen_server:call(Pid, clear),

    ?equal([], gtp_u_kmod_port:all(Pid)),

    meck_validate(Config),
    ok.

echo_server(Config, Parent) ->
    IfAddr = proplists:get_value(ifaddr, Config),
    {ok, S} = gen_udp:open(0, [{ip, IfAddr}, {active, false},
			       binary, {reuseaddr, true}]),
    {ok, {IP, Port}} = inet:sockname(S),

    proc_lib:init_ack(Parent, {ok, self(), IP, Port}),
    case gen_udp:recv(S, 4096, ?TIMEOUT) of
	{ok, {SrcIP, SrcPort, Msg}} ->
		gen_udp:send(S, SrcIP, SrcPort, Msg);
	Other ->
	    ct:fail(Other)
    end,
    gen_udp:close(S),
    Parent ! {self(), done}.

%%%===================================================================
%%% I/O and socket functions
%%%===================================================================

make_gtp_socket(Config) ->
    make_gtp_socket(Config, ?CLIENT_IP).

make_gtp_socket(Config, IP) ->
    make_gtp_socket(Config, IP, ?GTP1u_PORT).

make_gtp_socket(_Config, IP, Port) ->
    {ok, S} = gen_udp:open(Port, [{ip, IP}, {active, false},
				  binary, {reuseaddr, true}]),
    S.

send_pdu(S, Msg) ->
    send_pdu(S, ?TEST_GSN, Msg).

send_pdu(S, Peer, Msg) ->
    Data = gtp_packet:encode(Msg),
    ok = gen_udp:send(S, Peer, ?GTP1u_PORT, Data).

send_recv_pdu(S, Msg) ->
    send_recv_pdu(S, Msg, ?TIMEOUT).

send_recv_pdu(S, Msg, Timeout) ->
    send_recv_pdu(S, ?TEST_GSN, Msg, Timeout).

send_recv_pdu(S, Peer, Msg, Timeout) ->
    send_pdu(S, Peer, Msg),
    recv_pdu(S, Peer, Msg#gtp.seq_no, Timeout).

recv_pdu(S, Timeout) ->
    recv_pdu(S, ?TEST_GSN, Timeout).

recv_pdu(S, Peer, Timeout) ->
    recv_pdu(S, Peer, undefined, Timeout).

recv_pdu(S, Peer, SeqNo, Timeout) ->
    recv_pdu(S, Peer, SeqNo, Timeout, fun(Reason) -> ct:fail(Reason) end).

recv_pdu(_, _Peer, _SeqNo, Timeout, Fail) when Timeout =< 0 ->
    recv_pdu_fail(Fail, timeout);
recv_pdu(S, Peer, SeqNo, Timeout, Fail) ->
    Now = erlang:monotonic_time(millisecond),
    case gen_udp:recv(S, 4096, Timeout) of
	{ok, {Peer, _, Response}} ->
	    recv_pdu_msg(Response, Now, S, Peer, SeqNo, Timeout, Fail);
	{error, Error} ->
	    recv_pdu_fail(Fail, Error);
	Unexpected ->
	    recv_pdu_fail(Fail, Unexpected)
    end.

recv_pdu_msg(Response, At, S, Peer, SeqNo, Timeout, Fail) ->
    ct:pal("Msg: ~s", [pretty_print((catch gtp_packet:decode(Response)))]),
    case gtp_packet:decode(Response) of
	#gtp{type = echo_request} = Msg ->
	    Resp = Msg#gtp{type = echo_response, ie = []},
	    send_pdu(S, Resp),
	    NewTimeout = Timeout - (erlang:monotonic_time(millisecond) - At),
	    recv_pdu(S, Peer, SeqNo, NewTimeout, Fail);
	#gtp{seq_no = SeqNo} = Msg
	  when is_integer(SeqNo) ->
	    Msg;

	Msg ->
	    Msg
    end.

recv_pdu_fail(Fail, Why) when is_function(Fail) ->
    Fail(Why);
recv_pdu_fail(Fail, Why) ->
    {Fail, Why}.

%%%===================================================================
%%% Record formating
%%%===================================================================

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).

pretty_print(gtp, N) ->
    N = record_info(size, gtp) - 1,
    record_info(fields, gtp);
pretty_print(_, _) ->
    no.

%%%===================================================================
%%% TEID and SeqNo functions
%%%===================================================================

get_next_teid() ->
    ets:update_counter(?MODULE, teid, 1) rem 16#100000000.

get_next_seq_no() ->
    ets:update_counter(?MODULE, seq_no, 1) rem 16#10000.

%%%===================================================================
%%% Internal functions
%%%===================================================================

getfirst(_Fun, []) ->
    undefined;
getfirst(Fun, [H|T]) ->
    case Fun(H) of
	{true, Item} ->
	    Item;
	true ->
	    H;
	_ ->
	    getfirst(Fun, T)
    end.

make_g_pdu(TEID, Bin) ->
    #gtp{version = v1, type = g_pdu, tei = TEID, ie = Bin}.

validate_tunnel(Name, LocalTEI, RemoteIP, RemoteTEI) ->
    ?match({Pid, _} when is_pid(Pid), gtp_u_kmod:lookup({Name, LocalTEI})),
    ?match({Pid, _} when is_pid(Pid), gtp_u_kmod:lookup({Name, {remote, RemoteIP, RemoteTEI}})),
    ok.

%% keep this in sync with gtp_u_kmod_port
-record(tunnel, {seid, local_teid, peer_ip, peer_teid, ms, far_id}).

validate_tunnel(Pid, SEID, _GtpIntf, TEI,  PeerIP,  PeerTEI, _SgiIntf, MSv4) ->
    ?match([#tunnel{local_teid = TEI, peer_ip = PeerIP, peer_teid = PeerTEI,
		    ms = MSv4}], gtp_u_kmod_port:lookup(Pid, SEID)),
    ok.

make_sgi_session(SEID, GtpIntf, TEI, PeerIP, PeerTEI, SgiIntf, MSv4) ->
    IEs = #{cp_f_seid => SEID,
	    create_pdr => [#{pdr_id => 1, precedence => 100,
			     pdi => #{source_interface => GtpIntf,
				      local_f_teid => #f_teid{teid = TEI}},
			     outer_header_removal => true, far_id => 2},
			   #{pdr_id => 2, precedence => 100,
			     pdi => #{source_interface => SgiIntf,
				      ue_ip_address => {dst, MSv4}},
			     outer_header_removal => false, far_id => 1}],
	    create_far => [#{far_id => 1, apply_action => [forward],
			     forwarding_parameters => #{
			       destination_interface => GtpIntf,
			       outer_header_creation =>
				   #f_teid{ipv4 = PeerIP,
					   teid = PeerTEI}}},
			   #{far_id => 2, apply_action => [forward],
			     forwarding_parameters => #{
			       destination_interface => SgiIntf}}]
	   },
    {SEID, session_establishment_request, IEs}.

make_update_pdr(SEID, Intf, TEI) ->
    IEs = #{cp_f_seid => SEID,
	    update_pdr => [#{pdr_id => 1, precedence => 100,
			     pdi => #{source_interface => Intf,
				      local_f_teid => #f_teid{teid = TEI}},
			     outer_header_removal => true, far_id => 2}]
	   },
    {SEID, session_modification_request, IEs}.

make_update_far(SEID, Intf, PeerIP, PeerTEI) ->
    make_update_far(SEID, Intf, PeerIP, PeerTEI, false).

make_update_far(SEID, Intf, PeerIP, PeerTEI, SndEM) ->
    FAR0 = #{far_id => 1, apply_action => [forward],
	     update_forwarding_parameters => #{
	       destination_interface => Intf,
	       outer_header_creation =>
		   #f_teid{ipv4 = PeerIP,
			   teid = PeerTEI}}},
    FAR = if SndEM =:= true ->
		  FAR0#{sxsmreq_flags => [sndem]};
	     true ->
		  FAR0
	  end,
    IEs = #{cp_f_seid => SEID, update_far => [FAR]},
    {SEID, session_modification_request, IEs}.

make_forward_session(_SEID,
		     _LeftIntf,  _LeftTEI,  _LeftPeerIP,  _LeftPeerTEI,
		     _RightIntf, _RightTEI, _RightPeerIP, _RightPeerTEI) ->
    ct:fail(undefined).

ip2bin({A, B, C, D}) ->
    <<A:8, B:8, C:8, D:8>>;
ip2bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

ip_csum(<<>>, CSum) ->
    CSum;
ip_csum(<<Head:8/integer>>, CSum) ->
    CSum + Head * 256;
ip_csum(<<Head:16/integer, Tail/binary>>, CSum) ->
    ip_csum(Tail, CSum + Head).

ip_csum(Bin) ->
    CSum0 = ip_csum(Bin, 0),
    CSum1 = ((CSum0 band 16#ffff) + (CSum0 bsr 16)),
    ((CSum1 band 16#ffff) + (CSum1 bsr 16)) bxor 16#ffff.

make_udp(NwSrc, NwDst, TpSrc, TpDst, PayLoad) ->
    Id = 0,
    Proto = gen_socket:protocol(udp),

    UDPLength = 8 + size(PayLoad),
    UDPCSum = ip_csum(<<NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8,
			0:8, Proto:8, UDPLength:16,
			TpSrc:16, TpDst:16, UDPLength:16, 0:16,
			PayLoad/binary>>),
    UDP = <<TpSrc:16, TpDst:16, UDPLength:16, UDPCSum:16, PayLoad/binary>>,

    TotLen = 20 + size(UDP),
    HdrCSum = ip_csum(<<4:4, 5:4, 0:8, TotLen:16,
			Id:16, 0:16, 64:8, Proto:8,
			0:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>),
    IP = <<4:4, 5:4, 0:8, TotLen:16,
	   Id:16, 0:16, 64:8, Proto:8,
	   HdrCSum:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>,
    list_to_binary([IP, UDP]).
