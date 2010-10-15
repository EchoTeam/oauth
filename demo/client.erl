%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

-module(client).
-compile([export_all]).

run() ->
  [application:start(X) || X <- [crypto, inets, ssl]],

  {ok, Nonce} = nonce:start_link(),

  BaseURL = "http://CHANGE.THIS.NOW:8115/api",

  C = oauthclient:new([
    {access_token_api, {post, BaseURL ++ "/AccessToken"}},
    {authorization_url,
      {BaseURL ++ "/Authorize", [], []}},
    {callback_url, "oob"},
    {nonce_server, Nonce},
    {consumer_key, "consumer_key"},
    {consumer_secret, "consumer_secret"},
    {request_token_api, {post, BaseURL ++ "/RequestToken"}},
    {signature_method, hmac_sha1}
  ]),

  ResourceParam = {"resource", "1"},

  {C2, {ok, _}} = oauthclient:get_request_token(C, [ResourceParam]),
  {C3, {ok, AuthorizationURL}} = oauthclient:mk_authorization_url(C2),

  io:format("~s~n", [AuthorizationURL]),

  timer:sleep(15000),

  {C4, ok} =
    oauthclient:authorization_completed(C3, "no verifier for 1.0 server"),

  {C5, {ok, _}} = oauthclient:get_access_token(C4),

  AccessURL = BaseURL ++ "/Access",

  {_C6, {ok, {URL, Headers, ContentType, Body}}} =
    oauthclient:mk_access_request(
      C5, post, with_rest, AccessURL, [ResourceParam]
    ),

  Response = http:request(post, {URL, Headers, ContentType, Body}, [], []),

  io:format("Response: ~p~n", [Response]).
