%
% Copyright (c) 2008-2009 Jacknyfe, Inc., http://jacknyfe.net.
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

-module(test).
-compile(export_all).

run() ->
  %
  % XXX: Unit testing, ugly. :-) Should be somewhere else.
  %

  {error, missing_parameter, consumer_secret, _} = 
    oauth:generate_signature(hmac_sha1, []),

  {ok, "HMAC-SHA1", "tR3+Ty81lMeYAr/Fid0kMTYa/WM=", _} =
    oauth:generate_signature(hmac_sha1, [
      {consumer_secret, "kd94hf93k423kf44"},
      {endpoint, {"get", "http", "photos.example.net", 80, "/photos"}},
      {params, [
        {"oauth_consumer_key", "dpf43f3p2l4k3l03"},
        {"oauth_token", "nnch734d00sl2jdk"},
        {"oauth_timestamp", "1191242096"},
        {"oauth_nonce", "kllo9940pd9333jh"},
        {"oauth_version", "1.0"},
        {"file", "vacation.jpg"},
        {"size", "original"}
      ]},
      {token_secret, "pfkkdhi9sl3r4s00"}
    ]).

%%

signed_request() ->
  [application:start(X) || X <- [crypto, inets, ssl]],
  {ok, Nonce} = nonce:start_link(),

  SignParams = {"consumer key", "consumer secret", Nonce, hmac_sha1},

  [
    oauthclient:mk_signed_request(SignParams, HttpMethod, "http://js-kit.com",
      AuthParamsLocation, [{"a", "b"}])
    ||
    {HttpMethod, AuthParamsLocation} <- [
      {get, with_rest},
      {put, {authorization, "JS-Kit"}},
      {post, {authorization, "JS-Kit"}},
      {post, with_rest}
    ]
  ].

%%

termie_make_request(State, AccessURL, Params) ->
  {_C4, {ok, {URL, Headers, _ContentType, _Body}}} =
    oauthclient:mk_access_request(State, get, with_rest, AccessURL, Params),

  http:request(get, {URL, Headers}, [], []).

%%

termie_config(SignatureMethod) ->
  BaseURL = "http://term.ie/oauth/example",

  [
    {access_token_api, {get, BaseURL ++ "/access_token.php"}},
    {authorization_url,
      {BaseURL ++ "/not_implemented", [], []}},
    {callback_url, "oob"},
    {nonce_server, oauth_nonce},
    {consumer_key, "key"},
    {consumer_secret, "secret"},
    {request_token_api, {get, BaseURL ++ "/request_token.php"}},
    {signature_method, SignatureMethod}
  ].

%%

termie() ->
  [application:start(X) || X <- [crypto, inets, ssl]],

  {ok, _} = nonce:start_link(),

  AccessURL = "http://term.ie/oauth/example/echo_api.php",

  [
    begin
      C = oauthclient:new(termie_config(SignatureMethod)),

      {C2, Result2} = oauthclient:get_request_token(C, []),
      case Result2 of
        {ok, _} -> ok;
        {error, Error} -> io:format("get_request_token: ~p~n", [Error])
      end,

      {C21, ok} = oauthclient:authorization_completed(C2,
        "termie is oauth 1.0 server, so it doesn't need verification codes"
      ),

      {C3, {ok, _}} = oauthclient:get_access_token(C21),

      termie_make_request(C3, AccessURL,
        [{"method", atom_to_list(SignatureMethod)}])
    end
    || SignatureMethod <- [hmac_sha1, plaintext]
  ].

%%

google() ->
  [application:start(X) || X <- [crypto, inets, ssl]],

  {ok, Nonce} = nonce:start_link(),

  BaseURL = "https://www.google.com/accounts/OAuth",

  ProviderSettings = [
    {access_token_api, {get, BaseURL ++ "GetAccessToken"}},
    {authorization_url, {BaseURL ++ "AuthorizeToken", [], []}},
    {callback_url, "oob"},
    {debug_output, [http_requests]},
    {nonce_server, Nonce},
    {consumer_key, "google consumer key"},
    {consumer_secret, "google consumer secret"},
    {request_token_api, {get, BaseURL ++ "GetRequestToken"}},
    {signature_method, hmac_sha1}
  ],

  thread_state(
    oauthclient:new(ProviderSettings),
    fun(C) ->
      oauthclient:reinstantiate(ProviderSettings, oauthclient:dump_state(C))
    end,
    [
      fun(C) ->
        {C2, Result2} = oauthclient:get_request_token(C, [
          {"scope", "http://www.blogger.com/feeds/"}
        ]),

        case Result2 of
          {ok, _} -> io:format("got request token~n");
          {error, Error} -> io:format("get_request_token: ~p~n", [Error]);
          Unexpected ->
            erlang:error({unexpected_return, get_request_token, Unexpected})
        end,

        {ok, C2}
      end,

      fun(C) ->
        {C2, {ok, URL}} = oauthclient:mk_authorization_url(C),
        io:format("~n~n~nVisit this URL:~n~s~n~n", [URL]),
        {ok, C2}
      end,

      fun(C) ->
        {ok, [Code]} = io:fread('...and enter the verifier code: ', "~s"),
        {C2, ok} = oauthclient:authorization_completed(C, Code),
        {ok, C2}
      end,

      fun(C) ->
        {_C, {ok, _}} = oauthclient:get_access_token(C),
        io:format("got access token~n"),
        {ok, done}
      end
    ]
  ).

%%

thread_state(Seed, SeedF, []) -> SeedF(Seed);
thread_state(Seed, SeedF, [F|Funs]) ->
  {ok, NewSeed} = F(Seed),
  case NewSeed of
    done -> ok;
    NS -> thread_state(SeedF(NS), SeedF, Funs)
  end.
