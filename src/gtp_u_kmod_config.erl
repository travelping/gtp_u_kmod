%% Copyright 2016, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(gtp_u_kmod_config).

-compile({parse_transform, cut}).

%% API
-export([load_config/1, validate_options/2]).

-define(DefaultOptions, [{sockets, undefined}]).
-define(DefaultSocketOptions, [{ip, undefined}, {vrf, undefined}]).
-define(DefaultVrfOptions, [{routes, undefined}]).

%%%===================================================================
%%% API
%%%===================================================================

load_config(Config0) ->
    Config = validate_config(Config0),
    lists:foreach(fun load_socket/1, proplists:get_value(sockets, Config)),

    ok.

%%%===================================================================
%%% Options Validation
%%%===================================================================

validate_options(Fun, Opts0, Defaults) ->
    Opts = lists:ukeymerge(1, lists:keysort(1, proplists:unfold(Opts0)), lists:keysort(1, Defaults)),
    validate_options(Fun, Opts).

validate_options(_Fun, []) ->
        [];
validate_options(Fun, [Opt | Tail]) when is_atom(Opt) ->
        [Fun(Opt, true) | validate_options(Fun, Tail)];
validate_options(Fun, [{Opt, Value} | Tail]) ->
        [{Opt, Fun(Opt, Value)} | validate_options(Fun, Tail)].

validate_config(Options) ->
    validate_options(fun validate_option/2, Options, ?DefaultOptions).

validate_option(controller, Value)
  when is_atom(Value), Value /= undefined ->
    Value;
validate_option(sockets, Value) when is_list(Value), length(Value) >= 1 ->
    validate_options(fun validate_sockets_option/2, Value);
validate_option(_Opt, Value) ->
    Value.

validate_sockets_option(Name, Value) when is_atom(Name), is_list(Value) ->
    validate_options(fun validate_socket_option/2, Value, ?DefaultSocketOptions);
validate_sockets_option(Opt, Value) ->
    throw({error, {options, {Opt, Value}}}).

validate_socket_option(ip, Value)
  when is_tuple(Value) andalso
       (tuple_size(Value) == 4 orelse tuple_size(Value) == 8) ->
    Value;
validate_socket_option(netdev, Value)
  when is_list(Value); is_binary(Value) ->
    Value;
validate_socket_option(netns, Value)
  when is_list(Value); is_binary(Value) ->
    Value;
validate_socket_option(freebind, true) ->
    freebind;
validate_socket_option(vrf, Value) when is_list(Value), length(Value) >= 1 ->
    validate_options(fun validate_vrf_option/2, Value);
validate_socket_option(Opt, Value) ->
    throw({error, {options, {Opt, Value}}}).

validate_vrf_option(routes, Value)
  when is_list(Value), length(Value) >= 1 ->
    lists:map(fun validate_vrf_routes_option/1, Value);
validate_vrf_option(netdev, Value)
  when is_list(Value); is_binary(Value) ->
    Value;
validate_vrf_option(netns, Value)
  when is_list(Value); is_binary(Value) ->
    Value;
validate_vrf_option(Opt, Value) ->
    throw({error, {options, {Opt, Value}}}).

validate_vrf_routes_option({Prefix, PrefixLen} = Value)
  when is_tuple(Prefix) andalso is_integer(PrefixLen)  andalso
       (tuple_size(Prefix) == 4 orelse tuple_size(Prefix) == 8) ->
    Value;
validate_vrf_routes_option(Value) ->
    throw({error, {options, {route, Value}}}).

load_socket({Name, Options}) ->
    gtp_u_kmod:start_socket(Name, Options).
