%% Copyright 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_kmod_vrf).

-behaviour(gen_server).

-compile({parse_transform, cut}).

-include_lib("gen_socket/include/gen_socket.hrl").
-include_lib("gtplib/include/gtp_packet.hrl").
-include("include/gtp_u_kmod.hrl").

%% API
-export([start_vrf/2, start_link/2]).
-export([create_pdp_context/5, update_pdp_context/5, delete_pdp_context/5]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 terminate/2, code_change/3]).

-define(SERVER, ?MODULE).

-record(state, {name, netns, gtp_dev}).

%%%===================================================================
%%% API
%%%===================================================================

start_vrf(Name, Options) ->
    gtp_u_kmod_vrf_sup:new(Name, Options).

start_link(Name, Options) ->
    gen_server:start_link({local, vrf_reg_name(Name)}, ?MODULE, [Name, Options], []).

create_pdp_context(Socket, PeerIP, LocalTEI, RemoteTEI, {vrf, Name, Args}) ->
    vrf_call(Name, {create_pdp_context, Socket, PeerIP, LocalTEI, RemoteTEI, Args}).

update_pdp_context(Socket, PeerIP, LocalTEI, RemoteTEI, {vrf, Name, Args}) ->
    vrf_call(Name, {update_pdp_context, Socket, PeerIP, LocalTEI, RemoteTEI, Args}).

delete_pdp_context(Socket, PeerIP, LocalTEI, RemoteTEI, {vrf, Name, Args}) ->
    vrf_call(Name, {delete_pdp_context, Socket, PeerIP, LocalTEI, RemoteTEI, Args}).

vrf_call(Name, Request) ->
    try
	R = gen_server:call(vrf_reg_name(Name), Request),
	lager:debug("vrf_call: ~p", [R]),
	R
    catch
	exit:{noproc, _} ->
	    lager:error("noproc: ~p", [Name]),
	    {error, not_found};
	exit:Exit ->
	    lager:error("Exit: ~p", [Exit]),
	    {error, not_found}
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Name, Options]) ->
    %% TODO: better config validation and handling
    NetNs = proplists:get_value(netns, Options),

    {ok, GtpDev} = gtp_u_kmod_netns:create_vrf(NetNs, Options),
    State = #state{name = Name, netns = NetNs, gtp_dev = GtpDev},
    {ok, State}.

handle_call({create_pdp_context, Socket, PeerIP, LocalTEI, RemoteTEI, Args} = _Request,
	    _From, #state{netns = NetNs, gtp_dev = GtpDev} = State) ->
    lager:info("KMOD VRF Create PDP Context Call ~p: ~p", [_From, _Request]),

    Reply = gtp_u_kmod_netns:create_pdp_context(NetNs, 1, PeerIP, Args, GtpDev, Socket, LocalTEI, RemoteTEI),
    {reply, Reply, State};

handle_call({update_pdp_context, Socket, PeerIP, LocalTEI, RemoteTEI, Args} = _Request,
	    _From, #state{netns = NetNs} = State) ->
    lager:info("KMOD VRF Update PDP Context Call ~p: ~p", [_From, _Request]),

    Reply = gtp_u_kmod_netns:update_pdp_context(NetNs, 1, PeerIP, Args, Socket, LocalTEI, RemoteTEI),
    {reply, Reply, State};

handle_call({delete_pdp_context, Socket, PeerIP, LocalTEI, RemoteTEI, Args} = _Request,
	    _From, #state{netns = NetNs} = State) ->
    lager:info("KMOD VRF Delete PDP Context Call ~p: ~p", [_From, _Request]),

    Reply = gtp_u_kmod_netns:delete_pdp_context(NetNs, 1, PeerIP, Args, Socket, LocalTEI, RemoteTEI),
    {reply, Reply, State};

handle_call(_Request, _From, State) ->
    lager:info("VRF Call ~p: ~p", [_From, _Request]),
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(Info, State) ->
    lager:debug("VRF Info: ~p", [Info]),
    {noreply, State}.

terminate(_Reason, #state{netns = NetNs, gtp_dev = GtpDev}) ->
    gtp_u_kmod_netns:destroy_vrf(NetNs, GtpDev),
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

vrf_reg_name(Name) when is_atom(Name) ->
    BinName = iolist_to_binary(io_lib:format("vrf_~s", [Name])),
    binary_to_atom(BinName, latin1).
