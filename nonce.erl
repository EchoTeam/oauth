%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

%
% Nonce server
%

-module(nonce).
-behaviour(gen_server).

-export([
  % public API
  get_ts_nonce/1,
  start_link/0,

  % gen_server callbacks
  code_change/3,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  init/1,
  terminate/2
]).

-define(RESET_PERIOD, 5000).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Public API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

get_ts_nonce(ServerRef) ->
  gen_server:call(ServerRef, {get_ts_nonce}).


start_link() ->
  gen_server:start_link({local, oauth_nonce}, ?MODULE, args, []).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% gen_server callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.


handle_call({get_ts_nonce}, _From, {_LastTs, N}) ->
  Ts = get_ts(),
  Nonce = "jskitnonce" ++ "-" ++ integer_to_list(erlang:phash2(make_ref())),
  {reply, {Ts, Nonce}, {Ts, N + 1}};

handle_call(_Request, _From, State) ->
  {noreply, State}.


handle_cast(_Request, State) ->
  {noreply, State}.


handle_info({reset}, {LastTs, _N} = State) ->
  Ts = get_ts(),
  if
    % We saw last request this very second, so it's not yet safe to reset
    % Nonce value (otherwise there's a chance it won't be unique).
    Ts == LastTs -> {noreply, State};

    true -> {noreply, {LastTs, 0}}
  end.


init(_Args) ->
  timer:send_interval(?RESET_PERIOD, {reset}),
  {ok, {0, 0}}.


terminate(_Reason, _State) ->
  ok.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Internal functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

get_ts() ->
  {MegaSecs, Secs, _} = now(),
  MegaSecs * 1000000 + Secs.
