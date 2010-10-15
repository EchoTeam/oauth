%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
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

