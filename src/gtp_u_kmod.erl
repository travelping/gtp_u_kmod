%% Copyright 2016, 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_kmod).

-compile({parse_transform, cut}).

-behaviour(gen_server).

%% API
-export([start_link/1, start_socket/2, start_vrf/2]).

%% regine_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
	 code_change/3, terminate/2]).

%% --------------------------------------------------------------------
%% Include files
%% --------------------------------------------------------------------
-include_lib("stdlib/include/ms_transform.hrl").

-define(SERVER, 'gtp-u').

-record(state, {controller, state, tref, timeout}).

%%%===================================================================
%%% API
%%%===================================================================

start_link(Controller) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, [Controller], []).

%%
%% Initialize a new GTPv1-u socket
%%
start_socket(Name, Options) ->
    gtp_u_kmod_socket:start_socket(Name, Options).

%%
%% start VRF instance
%%
start_vrf(Name, Options) ->
    gtp_u_kmod_vrf:start_vrf(Name, Options).

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init([Controller]) ->
    State0 = #state{
		controller = Controller,
		state = disconnected,
		tref = undefined,
		timeout = 10
	       },
    State = connect(State0),
    {ok, State}.

handle_call({bind_socket, Socket}, _From, State) ->
    Reply = gtp_u_kmod_socket:bind(Socket),
    {reply, Reply, State};

handle_call({bind_vrf, VRF}, _From, State) ->
    Reply = gtp_u_kmod_socket:bind(VRF),
    {reply, Reply, State};

handle_call(_Request, _From, State) ->
    lager:warning("KMOD: unhandled call ~p, from ~p", [_Request, _From]),
    {reply, ok, State}.

handle_cast(_Cast, State) ->
    {noreply, State}.

handle_info({nodedown, Node}, State0) ->
    lager:warning("node down: ~p", [Node]),

    State1 = handle_nodedown(State0),
    State = start_nodedown_timeout(State1),
    {noreply, State};

handle_info(reconnect, State0) ->
    lager:warning("trying to reconnect"),
    State = connect(State0#state{tref = undefined}),
    {noreply, State};

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
	ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

start_nodedown_timeout(State = #state{tref = undefined, timeout = Timeout}) ->
    NewTimeout = if Timeout < 3000 -> Timeout * 2;
		    true           -> Timeout
		 end,
    TRef = erlang:send_after(Timeout, self(), reconnect),
    State#state{tref = TRef, timeout = NewTimeout};

start_nodedown_timeout(State) ->
    State.

connect(#state{controller = Controller} = State) ->
    case net_adm:ping(Controller) of
	pong ->
	    lager:warning("Controller ~p is up", [Controller]),
	    erlang:monitor_node(Controller, true),

	    State#state{state = connected, timeout = 10};
	pang ->
	    lager:warning("Controller ~p is down", [Controller]),
	    start_nodedown_timeout(State)
    end.

handle_nodedown(State) ->
    State#state{state = disconnected}.
