%
% Nonce server
%
% Copyright (c) 2008-2010 Jacknyfe, Inc. (dba Echo), http://aboutecho.com.
% All rights reserved.
% 
% Redistribution and use in source and binary forms, with or without 
% modification, are permitted provided that the following conditions are met:
% 
%  * Redistributions of source code must retain the above copyright notice,
%    this list of conditions and the following disclaimer.
%  * Redistributions in binary form must reproduce the above copyright notice, 
%    this list of conditions and the following disclaimer in the documentation 
%    and/or other materials provided with the distribution.
% 
% THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
% AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
% IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
% ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
% LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
% CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
% SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
% INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
% CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
% ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
% POSSIBILITY OF SUCH DAMAGE.
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
  {reply, {Ts, "jskitnonce" ++ integer_to_list(N)}, {Ts, N + 1}};

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
