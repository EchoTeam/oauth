%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

-module(demo_server).
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


access_resource(B, Token, Params) ->
  case proplists:get_value("resource", Params) of
    undefined -> [{status, 401}, {html, "No resource specified"}];
    Resource ->
      case gen_server:call(B, {get_token_info, Token}) of
        {access_token, _ConsumerKey, Resource} ->
          {html, "Here you go"};

        _ -> [{status, 401}, {html, "Invalid access token"}]
      end
  end.

%%

authorize_token(B, _A, Token, Params, _CallbackAction) ->
  % XXX: Of course this should also check if the user is logged in, if it's the
  % right user for the token, etc.
  case gen_server:call(B, {get_token_info, Token}) of
    {request_token, ConsumerKey, Resource} ->
      case proplists:get_value("action", Params) of
        "no" -> 
          gen_server:call(B, {deny_token, Token}),
          {html, "All right!"};

        "yes" ->
          gen_server:call(B, {authorize_token, Token}),
          {html, "Authorized!"};

        undefined ->
          {html, io_lib:format(
            "<form method=GET>Do you want to grant '~s' access to '~s'?<br>" ++
            "<select name=action><option>yes</option><option>no</option>" ++
            "</select><input type=submit>" ++
            "<input type=hidden name=oauth_token value=~s></form>",
            [ConsumerKey, Resource, Token]
            )
          };

        _ -> {html, "Invalid parameters"}
      end;

    _ -> {html, "Invalid request token"}
  end.

%%

get_consumer_secret(B, ConsumerKey) ->
  gen_server:call(B, {get_consumer_secret, ConsumerKey}).

%%

get_token_secret(B, ConsumerKey, Token) ->
  gen_server:call(B, {get_token_secret, ConsumerKey, Token}).

%%

init(_Arg) ->
  bookkeeper:start_link().

%%

issue_access_token(B, _ConsumerKey, RequestToken) ->
  case gen_server:call(B, {promote_token, RequestToken}) of
    {ok, Token, TokenSecret} -> {ok, Token, TokenSecret, []};
    {error, Reason} ->
      {error, Reason, [{status, 400}, {html, "Invalid token supplied"}]}
  end.

%%

issue_request_token(B, ConsumerKey, Params) ->
  case proplists:get_value("resource", Params) of
    undefined -> 
      {
        error,
        invalid_parameters,
        [{status, 400}, {html, "No resource to access is specified"}]
      };

    Resource ->
      gen_server:call(B, {issue_request_token, ConsumerKey, Resource})
  end.

%%

render_error(_B, ErrorCode, Params) ->
  oauthserver_stderr:render_error(ErrorCode, Params).

%%

saw_ts_nonce(B, ConsumerKey, Timestamp, Nonce) ->
  case gen_server:call(B, {check_ts_nonce, ConsumerKey, Timestamp, Nonce}) of
    ok -> false;
    {error, Reason, RetVal} -> {true, Reason, RetVal}
  end.
