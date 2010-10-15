%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

%
% This behviour file defines callbacks used by OAuth server framework.
%

-module(gen_oauthserver).
-export([behaviour_info/1]).

%
% yaws_arg() is the argument passed to out/1 by Yaws.
% yaws_retval() is any valid out/1 return value according to yaws_api(5).
%
% token() = string()
% token_secret() = string()
% kvpair() = {string(), string()}
%

%
% All callback functions (except init/1) receive an opaque Arg value, which
% itself gets returned by a call to init/1 during server initialization.
%
behaviour_info(callbacks) ->
  [
    %
    % access_resource(Arg, AccessToken, Params) -> yaws_retval()
    %
    % This function is called when a request to access a protected resource is
    % received and verified as valid. Note that though perceived as valid, the
    % access token might have expired etc, but this is entirely up to the
    % callback.
    %
    {access_resource, 3},

    %
    % authorize_token(Arg, YawsArg, Token, Params, CallbackAction)
    %   -> yaws_retval()
    %
    %   CallbackAction = undefined | yaws_retval()
    %
    % YawsArg = yaws_arg()
    % Token = token()
    % Params = [kvpair()]
    % CallbackAction = undefined | yaws_retval()
    %
    % Called when the user is required to authorize access to a resource for
    % specific token. Params is a list of {Key, Value} pairs from the request.
    % If the request contained a callback URL, CallbackAction is a proper
    % yaws_retval() redirecting to the URL; atom 'undefined' otherwise.
    %
    % YawsArg is the Yaws arg# structure containing all request data, so that
    % the callback can check for cookies, headers, etc.
    %
    {authorize_token, 5},

    %
    %
    % get_consumer_secret(Arg, ConsumerKey) -> {ok, string()} | not_found
    %
    % Called to look up a consumer secret by corresponding consumer key.
    %
    {get_consumer_secret, 2},

    %
    % get_token_secret(Arg, ConsumerKey, Token) -> {ok, string()} | not_found
    %
    % Called to look up a secret for a token, which is tied to a specific
    % consumer.
    %
    {get_token_secret, 3},

    %
    % init(InitArg) -> {ok, Arg}
    %
    % InitArg = term()
    %
    % Called at server initialization; returns an argument which is passed to
    % all subsequent calls to this instance of the server.
    %
    % InitArg is a value from the application environment.
    %
    {init, 1},

    %
    % issue_access_token(Arg, ConsumerKey, RequestToken) ->
    %   {ok, token(), token_secret(), [kvpair()]}
    % | {error, Reason, RetVal}
    %
    % Reason = token()
    % RetVal = yaws_retval()
    %
    % Called when a request token needs to be exchanged for an access token.
    % Might return a list of (extra) key/value pairs to be included into the
    % response.
    %
    % In case of errors returns Reason (solely for logging purposes) and the
    % value to return to Yaws.
    %
    {issue_access_token, 3},

    %
    % issue_request_token(Arg, ConsumerKey, Params) ->
    %   {ok, token(), token_secret(), [kvpair()]}
    % | {error, Reason, RetVal}
    %
    % Params = [kvpair()]
    % Reason = token()
    % RetVal = yaws_retval()
    %
    % Called when a consumer (identified by ConsumerKey) asks for a request
    % token. Params are the request parameters. Might return a list of (extra)
    % key/value pairs to be included into the response.
    %
    % In case of errors returns Reason (solely for logging purposes) and the
    % value to return to Yaws.
    %
    {issue_request_token, 3},

    %
    % render_error(Arg, ErrorCode, Param) -> yaws_retval()
    %
    % Called to render an error specified by ErrorCode with additional
    % parameter Param. For an exhaustive list of error codes and parameter
    % semantics refer to oauthserver_stderr.erl.
    %
    {render_error, 3},

    % 
    % saw_ts_nonce(Arg, ConsumerKey, Timestamp, Nonce) ->
    %   false | {true, Reason, RetVal}
    %
    % Reason = term()
    % RetVal = yaws_retval()
    %
    % Called to check whether:
    %  * the timestamp/nonce values from the consumer have already been seen;
    %  * if the timestamp value if less or equal to a previously used one.
    %
    % Reason is used internally (logged) while RetVal is passed back to Yaws
    % for output.
    %
    {saw_ts_nonce, 4}
  ];

behaviour_info(_) ->
  undefined.
