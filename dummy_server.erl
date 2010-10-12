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

-module(dummy_server).
-behaviour(gen_oauthserver).
-export([
  access_resource/3,
  authorize_token/5,
  get_consumer_secret/2,
  get_token_secret/3,
  init/1,
  issue_access_token/3,
  issue_request_token/3,
  render_error/3,
  saw_ts_nonce/4
]).


access_resource(_Arg, "at", _Params) ->
  {html, "Here you go"};

access_resource(_Arg, _AccessToken, _Params) ->
  [{status, 401}, {html, "Invalid access parameters"}].

%%

authorize_token(_Arg, _A, "tokenXXX" = Token, _Params, CallbackAction) ->
  error_logger:info_msg("Authorizing token: ~s~n", [Token]),
  case CallbackAction of
    undefined -> {html, "Authorized!"};
    _ -> CallbackAction
  end;

authorize_token(_Arg, _A, _Token, _Params, _CallbackAction) ->
  % XXX: this should be a 401 with WWW-Authenticate header, probably
  {html, "Invalid request token"}.

%%

get_consumer_secret(_Arg, "consumerkey") -> {ok, "djr9rjt0jd78jf88"};
get_consumer_secret(_Arg, "dpf43f3p2l4k3l03") -> {ok, "kd94hf93k423kf44"};
get_consumer_secret(_Arg, _Key) -> not_found.

%%

get_token_secret(_Arg, "consumerkey", "at") -> {ok, "atsecret"};
get_token_secret(_Arg, "dpf43f3p2l4k3l03", "at") -> {ok, "atsecret"};
get_token_secret(_Arg, "consumerkey", "tokenXXX") -> {ok, "secretXXX"};
get_token_secret(_Arg, "dpf43f3p2l4k3l03", "tokenXXX") -> {ok, "secretXXX"};
get_token_secret(_Arg, _ConsumerKey, _Token) -> not_found.

%%

init(_Arg) ->
  {ok, arg}.

%%

issue_access_token(_Arg, _ConsumerKey, _RequestToken) ->
  {ok, "at", "atsecret", [{"k", "v"}]}.

%%

issue_request_token(_Arg, _ConsumerKey, _Params) ->
  % XXX: make it a callback
  {ok, "tokenXXX", "secretXXX", []}.

%%

render_error(_Arg, ErrorType, Params) ->
  [{status, 500}, {html, io_lib:format("~s: ~p", [ErrorType, Params])}].

%%

saw_ts_nonce(example, _ConsumerKey, _Timestamp, _Nonce) ->
  {true, used_nonce, [{status, 401}, {html, "Invalid or used Nonce"}]};

saw_ts_nonce(_Arg, _ConsumerKey, _Timestamp, _Nonce) ->
  false.

