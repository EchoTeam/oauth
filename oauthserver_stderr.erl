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

%
% stderr - standard error messages for OAuth server framework.
% 
-module(oauthserver_stderr).
-export([render_error/2]).

render_error(access_token_extra_parameters, _) ->
  [
    {status, 403},
    {html,
      "Extra parameters forbidden for this API method (see " ++
      "<a href=\"http://oauth.net/core/1.0/#auth_step3\">" ++
      "section 6.3.1</a> of the OAuth Core 1.0)"
    }
  ];

render_error(duplicate_parameter, Par) ->
  [
    {status, 400}, 
    {html, io_lib:format("Parameter occurs more than once: ~s", [Par])}
  ];

render_error(invalid_api_method, URLPath) ->
  [
    {status, 404},
    {html, io_lib:format("Invalid API method: ~s", [URLPath])}
  ];

render_error(invalid_consumer_key, ConsumerKey) ->
  [
    {status, 401},
    {html, io_lib:format("Invalid consumer key: ~s", [ConsumerKey])}
  ];

render_error(invalid_host_header, Header) ->
  [
    {status, 400},
    {html, io_lib:format("Invalid 'Host' header: ~s", [Header])}
  ];

render_error(invalid_http_method, {Method, AllowedMethods}) ->
  [
    {status, 405},
    {header, io_lib:format("Allow: ~s", [AllowedMethods])},
    {html, io_lib:format("Method not allowed: ~s<br>Allowed: ~s~n",
      [Method, AllowedMethods])}
  ];

render_error(invalid_port_number_in_host_header, Port) ->
  [
    {status, 400},
    {html, io_lib:format("Invalid port number in 'Host' header: ~s", [Port])}
  ];

render_error(invalid_token, Token) ->
  [
    {status, 401},
    {html, io_lib:format("Invalid token: ~s", [Token])}
  ];

render_error(missing_required_parameter, Par) ->
  [
    {status, 400},
    {html, io_lib:format("Missing required parameter: '~s'~n", [Par])}
  ];

render_error(invalid_signature, _) ->
  [
    {status, 401},
    {html, "Invalid signature"}
  ];

render_error(ErrorCode, Params) ->
  [
    {status, 500},
    {html,
      io_lib:format("Unknown error condition: ~s (~p)", [ErrorCode, Params])
    }
  ].
