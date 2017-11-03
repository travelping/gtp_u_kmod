%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_kmod_port).

%% A GTP-U proxy instance is described by
%%  * GRX IP and sending port
%%  * Proxy IP and sending port
%%
%% It will open the GTPv1-U port (2152) for recieving
%% and open the specified sending ports on the GRP and
%% Proxy IP's

-behaviour(gen_server).

-include_lib("stdlib/include/ms_transform.hrl").
-include_lib("gen_socket/include/gen_socket.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include("include/gtp_u_kmod.hrl").

%% API
-export([start_sockets/0, start_link/1, port_reg_name/1, send/3, bind/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-ifdef(TEST).
%% Test API
-export([lookup/2, all/1]).
-endif.

-define(SERVER, ?MODULE).

-record(state, {name, ip, owner, gtp0, gtp1u, gtp_dev, tid}).
-record(tunnel, {seid, local_teid, peer_ip, peer_teid, ms, far_id}).

-define('Tunnel Endpoint Identifier Data I', {tunnel_endpoint_identifier_data_i, 0}).

%%%===================================================================
%%% API
%%%===================================================================

start_sockets() ->
    {ok, Sockets} = application:get_env(sockets),
    lists:foreach(fun(Socket) ->
			  gtp_u_kmod_port_sup:new(Socket)
		  end, Sockets),
    ok.

start_link({Name, SocketOpts}) ->
    RegName = port_reg_name(Name),
    lager:info("RegName: ~p", [RegName]),
    gen_server:start_link({local, RegName}, ?MODULE, [Name, SocketOpts], []).

port_reg_name(Name) when is_atom(Name) ->
    BinName = iolist_to_binary(io_lib:format("port_~s", [Name])),
    binary_to_atom(BinName, latin1).

send(Pid, IP, Data) ->
    gen_server:cast(Pid, {send, IP, ?GTP1u_PORT, Data}).

bind(Name, Owner) ->
    lager:info("RegName: ~p", [port_reg_name(Name)]),
    case erlang:whereis(port_reg_name(Name)) of
	Pid when is_pid(Pid) ->
	    gen_server:call(Pid, {bind, Owner});
	_ ->
	    {reply, {error, not_found}}
    end.

-ifdef(TEST).
lookup(Pid, SEID) ->
    gen_server:call(Pid, {lookup, SEID}).

all(Pid) ->
    gen_server:call(Pid, all).
-endif.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Name, SocketOpts]) ->
    %% TODO: better config validation and handling
    IP    = proplists:get_value(ip, SocketOpts),
    NetNs = proplists:get_value(netns, SocketOpts),

    {ok, GTP0} = make_gtp_socket(NetNs, IP, ?GTP0_PORT, SocketOpts),
    {ok, GTP1u} = make_gtp_socket(NetNs, IP, ?GTP1u_PORT, SocketOpts),

    FD0 = gen_socket:getfd(GTP0),
    FD1u = gen_socket:getfd(GTP1u),
    {ok, GTPDev} = gtp_u_kernel:dev_create("gtp0", FD0, FD1u, SocketOpts),

    TID = ets:new(?SERVER, [ordered_set, {keypos, #tunnel.seid}]),

    State = #state{name = Name,
		   ip = IP,
		   tid = TID,
		   gtp0 = GTP0,
		   gtp1u = GTP1u,
		   gtp_dev = GTPDev},
    {ok, State}.

handle_call({lookup, SEID}, _From, #state{tid = TID} = State) ->
    Reply = ets:lookup(TID, SEID),
    {reply, Reply, State};

handle_call(all, _From, #state{tid = TID} = State) ->
    Reply = ets:tab2list(TID),
    {reply, Reply, State};

handle_call({bind, Owner}, _From, #state{ip = IP} = State) ->
    Reply = {ok, self(), IP},
    {reply, Reply, State#state{owner = Owner}};

handle_call({SEID, session_establishment_request, SER} = _Request,
	    _From, #state{gtp_dev = GTPDev, tid = TID} = State) ->

    lager:info("KMOD Port Session Establishment Request ~p: ~p", [_From, _Request]),

    Tunnel0 = #tunnel{seid = SEID},
    Tunnel1 = lists:foldr(fun create_pdr/2, Tunnel0, maps:get(create_pdr, SER, [])),
    Tunnel = lists:foldr(fun create_far/2, Tunnel1, maps:get(create_far, SER, [])),

    ets:insert_new(TID, Tunnel),
    #tunnel{local_teid = LocalTEI, peer_ip = PeerIP,
	    peer_teid = PeerTEI, ms = IPv4} = Tunnel,
    Reply = gtp_u_kernel:create_pdp_context(GTPDev, 1, PeerIP, IPv4, LocalTEI, PeerTEI),
    {reply, Reply, State};

handle_call({SEID, session_modification_request, SMR} = _Request,
	    _From, #state{gtp_dev = GTPDev, tid = TID} = State) ->

    lager:info("KMOD Port Session Modification Request ~p: ~p", [_From, _Request]),
    Reply =
	case ets:take(TID, SEID) of
	    [#tunnel{local_teid = OldLocalTEI, ms = OldIPv4} = Tunnel0] ->
		Tunnel1 = lists:foldr(fun update_pdr/2, Tunnel0, maps:get(update_pdr, SMR, [])),
		Tunnel = lists:foldr(fun update_far/2, Tunnel1, maps:get(update_far, SMR, [])),
		#tunnel{local_teid = LocalTEI, peer_ip = PeerIP,
			peer_teid = PeerTEI, ms = IPv4} = Tunnel,
		Replace = OldLocalTEI /= LocalTEI orelse OldIPv4 /= IPv4,
		case gtp_u_kernel:update_pdp_context(GTPDev, 1, PeerIP, IPv4, LocalTEI,
						     PeerTEI, Replace) of
		    ok ->
			ets:insert_new(TID, Tunnel),
			ok;
		    Other ->
			%% put old tunnel object back
			ets:insert_new(TID, Tunnel0),
			Other
		end;
	    _ ->
		{error, not_found}
	end,
    {reply, Reply, State};

handle_call({SEID, session_deletion_request, _} = _Request,
	    _From, #state{gtp_dev = GTPDev, tid = TID} = State) ->

    lager:info("KMOD Session Deletion Request ~p: ~p", [_From, _Request]),
    case ets:take(TID, SEID) of
	[#tunnel{local_teid = LocalTEI, peer_ip = PeerIP, peer_teid = PeerTEI, ms = IPv4}] ->
	    Reply = gtp_u_kernel:delete_pdp_context(GTPDev, 1, PeerIP, IPv4, LocalTEI, PeerTEI),
	    {reply, Reply, State};
	_ ->
	    {reply, {error, not_found}, State}
    end;

handle_call(clear, _From, #state{gtp_dev = GTPDev, tid = TID} = State) ->
    lager:info("KMOD clear request"),
    ets:foldl(fun(#tunnel{local_teid = LocalTEI, peer_ip = PeerIP,
			  peer_teid = PeerTEI, ms = IPv4}, _) ->
		      gtp_u_kernel:delete_pdp_context(GTPDev, 1, PeerIP, IPv4,
						      LocalTEI, PeerTEI),
		      ok end, ok, TID),
    ets:delete_all_objects(TID),
    {reply, ok, State};

handle_call(_Request, _From, State) ->
    lager:info("KMOD Port Call ~p: ~p", [_From, _Request]),
    Reply = ok,
    {reply, Reply, State}.

handle_cast({send, IP, Port, Data}, #state{gtp1u = GTP1u} = State) ->
    R = gen_socket:sendto(GTP1u, {inet4, IP, Port}, Data),
    lager:debug("Send Result: ~p", [R]),
    {noreply, State};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info({Socket, input_ready}, State) ->
    handle_input(Socket, State);

handle_info(Info, State) ->
    lager:debug("Info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================
make_gtp_socket(NetNs, {_,_,_,_} = IP, Port, Opts) when is_list(NetNs) ->
    {ok, Socket} = gen_socket:socketat(NetNs, inet, dgram, udp),
    bind_gtp_socket(Socket, IP, Port, Opts);
make_gtp_socket(_NetNs, {_,_,_,_} = IP, Port, Opts) ->
    {ok, Socket} = gen_socket:socket(inet, dgram, udp),
    bind_gtp_socket(Socket, IP, Port, Opts).

bind_gtp_socket(Socket, {_,_,_,_} = IP, Port, Opts) ->
    case proplists:get_bool(freebind, Opts) of
	true ->
	    ok = gen_socket:setsockopt(Socket, sol_ip, freebind, true);
	_ ->
	    ok
    end,
    lists:foreach(fun(Opt) -> socket_setopts(Socket, Opt) end, Opts),
    ok = gen_socket:bind(Socket, {inet4, IP, Port}),
    ok = gen_socket:setsockopt(Socket, sol_ip, recverr, true),
    ok = gen_socket:input_event(Socket, true),
    {ok, Socket}.

socket_setopts(Socket, {netdev, Device})
  when is_list(Device); is_binary(Device) ->
    BinDev = iolist_to_binary([Device, 0]),
    ok = gen_socket:setsockopt(Socket, sol_socket, bindtodevice, BinDev);
socket_setopts(_Socket, _) ->
    ok.

handle_input(Socket, State) ->
    case gen_socket:recvfrom(Socket) of
	{error, _} ->
	    handle_err_input(Socket, State);

	{ok, {inet4, IP, Port}, Data} ->
	    ok = gen_socket:input_event(Socket, true),
	    handle_msg(Socket, IP, Port, Data, State);

	Other ->
	    lager:error("got unhandled input: ~p", [Other]),
	    ok = gen_socket:input_event(Socket, true),
	    {noreply, State}
    end.

handle_err_input(Socket, State) ->
    case gen_socket:recvmsg(Socket, ?MSG_DONTWAIT bor ?MSG_ERRQUEUE) of
	Other ->
	    lager:error("got unhandled error input: ~p", [Other]),
	    ok = gen_socket:input_event(Socket, true),
	    {noreply, State}
    end.

handle_msg(Socket, IP, Port, Data, State) ->
    try gtp_packet:decode(Data) of
	Msg = #gtp{version = v1} ->
	    lager:debug("Msg: ~p", [lager:pr(Msg, ?MODULE)]),
	    handle_msg_1(Socket, IP, Port, Msg, State);

	Other ->
	    lager:debug("Msg: ~p", [Other]),
	    {noreply, State}
    catch
	Class:Error ->
	    lager:debug("Info Error: ~p:~p", [Class, Error]),
	    {noreply, State}
    end.

handle_msg_1(Socket, IP, Port,
	     #gtp{version = v1, type = echo_request, tei = TEI, seq_no = SeqNo}, State) ->

    lager:debug("Echo Request from ~p:~w, TEI: ~w, SeqNo: ~w", [IP, Port, TEI, SeqNo]),
    %% GTP-u does not use the recovery IE, but it needs to be present
    %%
    %% 3GPP, TS 29.281, Section 7.2.2:
    %%   The Restart Counter value in the Recovery information element shall not be
    %%   used, i.e. it shall be set to zero by the sender and shall be ignored by
    %%   the receiver. The Recovery information element is mandatory due to backwards
    %%   compatibility reasons.
    ResponseIEs = [#recovery{restart_counter = 0}],

    Response = #gtp{version = v1, type = echo_response, tei = TEI, seq_no = SeqNo, ie = ResponseIEs},
    Data = gtp_packet:encode(Response),
    R = gen_socket:sendto(Socket, {inet4, IP, Port}, Data),
    lager:debug("Echo Reply Send Result: ~p", [R]),

    {noreply, State};

handle_msg_1(Socket, IP, Port,
	     #gtp{version = v1, type = g_pdu, tei = TEI, seq_no = _SeqNo},
	     State)
  when is_integer(TEI), TEI /= 0 ->
    lager:error("g_pdu from ~p:~w, TEI: ~w, SeqNo: ~w", [IP, Port, TEI, _SeqNo]),

    ResponseIEs = [#tunnel_endpoint_identifier_data_i{tei = TEI},
		   #gsn_address{address = ip2bin(IP)}],
    ExtHdr = [{udp_port, Port}],
    Response = #gtp{version = v1, type = error_indication, tei = 0,
		    seq_no = 0, ext_hdr = ExtHdr, ie = ResponseIEs},
    Data = gtp_packet:encode(Response),
    R = gen_socket:sendto(Socket, {inet4, IP, Port}, Data),
    lager:debug("Error Indication Send Result: ~p", [R]),

    {noreply, State};

handle_msg_1(_Socket, IP, _Port, #gtp{type = error_indication} = Msg, State) ->
    error_indication_report(IP, Msg, State),
    {noreply, State};

handle_msg_1(_Socket, IP, Port,
	     #gtp{version = v1, type = Type, tei = TEI, seq_no = SeqNo} = _Msg,
	     State) ->
    lager:error("~s from ~p:~w, TEI: ~w, SeqNo: ~w", [Type, IP, Port, TEI, SeqNo]),
    {noreply, State};

handle_msg_1(_Socket, _IP, _Port, _Msg, State) ->
    {noreply, State}.

error_indication_report(IP,
			#gtp{ie =
				 #{{gsn_address,0} :=
				       #gsn_address{address = PeerIP},
				   ?'Tunnel Endpoint Identifier Data I' :=
				       #tunnel_endpoint_identifier_data_i{tei = PeerTEI}}
			    },
			#state{owner = Owner, tid = TID})
  when is_pid(Owner) ->
    MS = #tunnel{seid = '$1', local_teid = '_',
		 peer_ip = bin2ip(PeerIP), peer_teid = PeerTEI,
		 ms = '_', far_id = '_'},
    case ets:match(TID, MS) of
	[[SEID]] ->
	    FTEID = #f_teid{ipv4 = IP, teid = PeerTEI},
	    SRR = #{
	      report_type => [error_indication_report],
	      error_indication_report =>
		  [#{remote_f_teid => FTEID}]
	     },
	    Owner ! {SEID, session_report_request, SRR};
	_ ->
	    ok
    end;
error_indication_report(_IP, _Msg, _State) ->
    ok.

%%====================================================================
%% IP helpers
%%====================================================================

ip2bin(IP) when is_binary(IP) ->
    IP;
ip2bin({A, B, C, D}) ->
    <<A, B, C, D>>;
ip2bin({A, B, C, D, E, F, G, H}) ->
    <<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>.

bin2ip(<<A, B, C, D>>) ->
    {A, B, C, D};
bin2ip(<<A:16, B:16, C:16, D:16, E:16, F:16, G:16, H:16>>) ->
    {A, B, C, D, E, F, G, H}.

%%====================================================================
%% Sx DP API helpers
%%====================================================================

create_pdr(#{pdi := #{
	       local_f_teid := #f_teid{teid = LocalTEI}
	      },
	     outer_header_removal := true
	    }, Tunnel) ->
    Tunnel#tunnel{
      local_teid = LocalTEI
     };
create_pdr(#{pdi := #{
	       ue_ip_address := {dst, IPv4}
	      },
	     outer_header_removal := false,
	     far_id := FarId}, Tunnel) ->
    Tunnel#tunnel{
      far_id = FarId,
      ms = IPv4
     }.

create_far(#{far_id := FarId,
	     apply_action := [forward],
	     forwarding_parameters := #{
	       outer_header_creation :=
		   #f_teid{
		      ipv4 = PeerIP,
		      teid = PeerTEI
		     }
	      }
	    }, #tunnel{far_id = FarId} = Tunnel) ->
    Tunnel#tunnel{
      peer_ip = PeerIP,
      peer_teid = PeerTEI
     };
create_far(_, Tunnel) ->
    Tunnel.

update_pdr(#{pdi := #{
	       local_f_teid := #f_teid{teid = LocalTEI}
	      },
	     outer_header_removal := true
	    }, Tunnel) ->
    Tunnel#tunnel{
      local_teid = LocalTEI
     };
update_pdr(_, Tunnel) ->
    Tunnel.

update_far(#{far_id := FarId,
	     apply_action := [forward],
	     update_forwarding_parameters := #{
	       outer_header_creation :=
		   #f_teid{
		      ipv4 = PeerIP,
		      teid = PeerTEI
		     }
	      }
	    }, #tunnel{far_id = FarId} = Tunnel) ->
    Tunnel#tunnel{
      peer_ip = PeerIP,
      peer_teid = PeerTEI
     };
update_far(_, Tunnel) ->
    Tunnel.
