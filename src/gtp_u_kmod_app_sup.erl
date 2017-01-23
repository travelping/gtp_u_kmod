%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_kmod_app_sup).

-behaviour(supervisor).

%% API
-export([start_link/0, start_controller/1]).

%% Supervisor callbacks
-export([init/1]).

%% Helper macro for declaring children of supervisor
-define(CHILD(I, Type, Args), {I, {I, start_link, Args}, permanent, 5000, Type, [I]}).

%% ===================================================================
%% API functions
%% ===================================================================

start_link() ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, []).

start_controller(Controller) ->
    supervisor:start_child(?MODULE, ?CHILD(gtp_u_kmod, worker, [Controller])).

%% ===================================================================
%% Supervisor callbacks
%% ===================================================================

init([]) ->
    {ok, {{one_for_one, 5, 10}, [?CHILD(gtp_u_kmod_netns_sup, supervisor, []),
				 ?CHILD(gtp_u_kmod_vrf_sup, supervisor, []),
				 ?CHILD(gtp_u_kmod_socket_sup, supervisor, [])
				]} }.
