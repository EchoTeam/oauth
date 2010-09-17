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

-module(client).
-compile([export_all]).

run() ->
  [application:start(X) || X <- [crypto, inets, ssl]],

  {ok, Nonce} = nonce:start_link(),

  BaseURL = "http://CHANGE.THIS.NOW:8115/api",

  C = oauthclient:new([
    {access_token_api, {post, BaseURL ++ "/AccessToken"}},
    {authorization_url,
      {BaseURL ++ "/Authorize", [callback_optional], []}},
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

  timer:sleep(10000),

  {C4, {ok, _}} = oauthclient:get_access_token(C3),

  AccessURL = BaseURL ++ "/Access",

  {_C5, {ok, {URL, Headers, ContentType, Body}}} =
    oauthclient:mk_access_request(
      C4, post, with_rest, AccessURL, [ResourceParam]
    ),

  Response = http:request(post, {URL, Headers, ContentType, Body}, [], []),

  io:format("Response: ~p~n", [Response]).
