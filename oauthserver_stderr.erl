%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
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
