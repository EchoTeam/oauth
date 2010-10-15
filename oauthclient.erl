%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

%
% OAuth client
%

-module(oauthclient).

%
% Public API:
%
% Generally the workflow is:
%   * new
%   * get_request_token
%   * mk_authorization_url
%   * authorization_completed
%   * get_access_token
%   * mk_access_request
%
% ====================================================================== 
%
% authorization_completed(State, Verifier) -> {NewState, ok}
%
% Make the client aware that the user has authorized the request token. 
% Verifier is the verification code passed via the callback or "out-of-band"
% measures (e.g. the user typed that in).
%
% ====================================================================== 
%
% authorization_failed(State) -> {NewState, ok}
%
% Make the client aware that the user has denied authorization of the request
% token. After calling this function it's ok to start over again, obtaining
% another request token.
%
% ====================================================================== 
%
% dump_state(State) -> StateDump
%
% This function dumps state bits that are *internal*, i.e. do not belong to
% the configuration passed to new/*. The output is a tuple (including the
% format version number) that can be passed to reinstantiate/2 to re-create the
% current state.
%
% ====================================================================== 
%
% get_access_token(State) ->
%   {NewState, {ok, Params}} | {NewState, {error, Reason}}
%
% get_access_token(State, ExtraParams) ->
%   {NewState, {ok, Params}} | {NewState, {error, Reason}}
%
% Exchange an authorized request token for an access token, optionally passing
% additional parameters ExtraParams. Returns key-value pairs (Params) returned
% by the server.
%
% ====================================================================== 
%
% get_opaque(State) -> term
%
% Return the opaque value contained in the state.
%
% ====================================================================== 
%
% get_request_token(State, Params) ->
%   {NewState, {ok, RequestToken}} | {NewState, {error, Reason}}
%
% Obtains a request token from the server. Params is a proplist of additional
% parameters in the HTTP request (both keys and values are strings).
%
% ====================================================================== 
%
% mk_access_request(State, HttpMethod, AuthParamsLocation, BaseURL, Params) ->
%   {NewState, {ok, {URL, Headers, ContentType, Body}}}
%
% HttpMethod = delete | get | post | put
% AuthParamsLocation = {authorization, Realm} | with_rest
% Realm = @string | none
%
% Construct a request for a protected resource located at BaseURL, using given
% HttpMethod. Authentication parameters are placed either into "Authorization"
% HTTP header (with Realm, if needed) or along with the rest of parameters
% (e.g. into the URL or request body).
% 
% ====================================================================== 
%
% mk_authorization_url(State) -> {NewState, {ok, URL}}
%
% Returns a URL that the user has to visit to authorize the request token.
%
% ====================================================================== 
%
% mk_signed_request(SignDetails, HttpMethod, URL, AuthParamsLocation, Params) ->
%   {URL, Headers, ContentType, Body}
%
%  SignDetails = {ConsumerKey, ConsumerSecret, Nonce, SignMethod}
%
% XXX: This does not really belong to OAuth. This is basically a function to
% make a request signed as per OAuth specification.
%
% See also:
%  * http://niallohiggins.com/2009/03/13/opensocial-and-2-legged-oauth/
%
% ====================================================================== 
%
% new(Args) -> State
%
% Initializes OAuth client according to Args and returns its state.
%
% XXX: Args needs to be documented. Check out test.erl for examples.
%
% ====================================================================== 
%
% new(Args, InitialState, Params)
%
% Do not use unless you know what you are doing.
%
% ====================================================================== 
%
% reinstantiate(Args, StateDump) -> NewState
%
% Reinstantiate OAuth client state from the StateDump. Args is the same as in
% call to new/*.
%
% ====================================================================== 
%
% set_opaque(State, Opaque) -> NewState
%
% Set opaque value in the state to Opaque.
%

-export([
  authorization_completed/2,
  authorization_failed/1,
  dump_state/1,
  get_access_token/1,
  get_access_token/2,
  get_opaque/1,
  get_request_token/2,
  mk_access_request/5,
  mk_authorization_url/1,
  mk_signed_request/5,
  new/1,
  new/3,
  reinstantiate/2,
  set_opaque/2
]).

-record(state, {
  access_token_api,
  access_token_renewal_allowed,
  authorization_url,
  callback_url,
  consumer_key,
  consumer_secret,
  debug_output,
  nonce_server,
  opaque,
  private_key,
  request_token_api,
  server_version,
  signature_method,
  state = initial,
  token,
  token_secret,
  verifier
}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Public API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

authorization_completed(State, Verifier) ->
  #state{ state = have_request_token } = State,

  {
    State#state{
      state = have_authorized_token,
      verifier = Verifier
    },
    ok
  }.

%% 

authorization_failed(State) ->
  State#state{ state = initial }.

%%

dump_state(State) ->
  {
    1,  % format version number
    State#state.opaque,
    State#state.state,
    State#state.server_version,
    State#state.token,
    State#state.token_secret,
    State#state.verifier
  }.


%%

get_access_token(State) -> get_access_token(State, []).

%
% OAuth Core specification v.1.0 explicitly forbids[1] passing application
% parameters in "get access token" request. However, some providers adhere to
% OAuth extensions[2] and thus warrant an option to bypass this restriction.
%
% [1]: http://oauth.net/core/1.0#auth_step3
% [2]: http://oauth.googlecode.com/svn/spec/ext/session/1.0/drafts/1/spec.html
%
get_access_token(#state{ state = CurState } = State, AppParams) ->
  AllowedStates = [have_authorized_token] ++ 
    case State#state.access_token_renewal_allowed of
      true -> [have_access_token];
      false -> []
    end,

  case lists:member(CurState, AllowedStates) of
    true -> ok;
    false ->
      erlang:error({get_access_token,
        {invalid_state, CurState}, 
        {allowed_states, AllowedStates}
      })
  end,

  {Method, URL} = State#state.access_token_api,

  {ContentType, Body, _, _} = prepare_request_params(
    State, 

    [{"oauth_token", State#state.token}]
    ++
    case State#state.server_version of
      '1.0' -> [];
      '1.0a' -> [{"oauth_verifier", State#state.verifier}]
    end,

    AppParams,

    [
      create_endpoint_param(Method, URL),
      {token_secret, State#state.token_secret}
    ]
  ),

  Headers = [],

  handle_response(
    State,
    
    http_request(State, Method, URL, ContentType, Body, Headers),
    
    CurState,
    
    [
      fun({Params, Token, TokenSecret}) ->
        {
          set_state(State, have_access_token, [
              {token, Token}, 
              {token_secret, TokenSecret}
          ]),

          {ok, Params}
        }
      end
    ]
  ).

%%

get_opaque(State) -> State#state.opaque.

%%

get_request_token(State, AppParams) ->
  #state{ state = initial } = State,

  {Method, URL} = State#state.request_token_api,

  {"application/x-www-urlencoded" = ContentType, Body, _, _} =
    prepare_request_params(
      State, 
      [
        % OAuth 1.0a requires the callback to be present when obtaining a
        % request token.
        {"oauth_callback", State#state.callback_url}
      ],
      AppParams,
      [
        create_endpoint_param(Method, URL),
        {token_secret, ""}
      ]
    ),

  Headers = [],

  handle_response(
    State,

    http_request(State, Method, URL, ContentType, Body, Headers),

    initial,

    [
      fun({Params, OAuthToken, OAuthTokenSecret}) ->
          %
          % This parameter is only returned by 1.0a servers
          % See section 6.1.2 of http://oauth.googlecode.com/svn/spec/core/1.0a/drafts/3/oauth-core-1_0a.html
          %
          ServerVersion =
            case proplists:get_value("oauth_callback_confirmed", Params) of
              "true" -> '1.0a';
              _ -> '1.0'
            end,

        {
          State#state{
            server_version = ServerVersion,
            state = have_request_token,
            token = OAuthToken,
            token_secret = OAuthTokenSecret
          },

          {ok, OAuthToken}
        }
      end
    ]
  ).

%%

mk_access_request(State, HttpMethod, AuthParamsLocation, URL, Params) ->
  #state{ state = have_access_token } = State,

  {"application/x-www-urlencoded" = ContentType, AllParams, AppParams,
    AuthParams} = prepare_request_params(
      State,

      % XXX: when this function is called by mk_signed_request (which is a
      % hack), the token is undefined.
      [ {K, V} 
        || {K, V} <- [{"oauth_token", State#state.token}],
        V =/= undefined
      ],

      Params,
      [
	create_endpoint_param(HttpMethod, URL),
        {token_secret, State#state.token_secret}
      ]
    ),

  {Headers, OutParams} =
    case AuthParamsLocation of
      {authorization, Realm} ->
        {
          [{"authorization",
            "OAuth " ++
            case Realm of
              none -> "";
              _ -> "realm=\"" ++ Realm ++ "\", "
            end ++ string:join(
              [ oauth:percent_encode(K) ++ "=\"" ++ oauth:percent_encode(V) ++
                "\"" || {K, V} <- AuthParams
              ],
              ", "
            )
          }],
          AppParams
        };
        
      with_rest -> {[], AllParams}
    end,

  CompleteURL = case OutParams of
    [] -> URL;
    _ -> URL ++ "?" ++ OutParams
  end,

  SimpleResp = {CompleteURL, Headers, unknown, none},

  {
    State,
    {
      ok,
      case HttpMethod of
        delete -> SimpleResp;
        get -> SimpleResp;
        post -> {URL, Headers, ContentType, OutParams};
        put -> SimpleResp
      end
    }
  }.


%%

mk_authorization_url(State) ->
  #state{ state = have_request_token } = State,

  {URL, Options, Params} = State#state.authorization_url,

  CompleteParams = Params ++
    case lists:member(token_optional, Options) of
      true -> [];
      false -> [{"oauth_token", State#state.token}]
    end
    ++
    case State#state.server_version of
      '1.0a' -> [];
      '1.0' ->
        case State#state.callback_url of
          % We are talking to a 1.0 server, which doesn't require us to
          % provide a callback URL. However our API requires the application to
          % supply us with one; exceptions are denoted as "oob" (out of band)
          % per OAuth 1.0a spec.
          %
          % So if we are talking to a 1.0 server AND the callback url is
          % specified as "oob", we can just omit it. It won't break the
          % protocol.
          "oob" -> [];
          CB -> [{"oauth_callback", CB}]
        end;

      Unexpected ->
        erlang:error({unexpected_server_version, Unexpected})
    end,

  {
    State,
    {
      ok,
      URL ++
      case CompleteParams of
        [] -> "";
        _ -> 
          {"application/x-www-urlencoded", Encoded} =
            oauth:encode_parameters(CompleteParams),
          "?" ++ Encoded
      end
    }
  }.

%%

mk_signed_request(SignDetails, HttpMethod, URL, AuthParamsLocation, Params) ->

  {ConsumerKey, ConsumerSecret, Nonce, SignMethod} = SignDetails,

  {_NewState, Result} =
    mk_access_request(
      #state {
        consumer_key = ConsumerKey,
        consumer_secret = ConsumerSecret,
        nonce_server = Nonce,
        signature_method = SignMethod,
        state = have_access_token,
        token_secret = "" % so that generate_signature doesn't complain
      },
      HttpMethod, AuthParamsLocation, URL, Params),

  Result.


%%

new(Args) ->
  AuthorizationURL = get_mandatory_value(Args, authorization_url),

  CallbackURL = get_mandatory_value(Args, callback_url),

  SignatureMethod = get_mandatory_value(Args, signature_method),
  PrivateKey = case SignatureMethod of
    rsa_sha1 -> get_mandatory_value(Args, private_key);
    _ -> not_needed
  end,

  #state{
    access_token_api = get_mandatory_value(Args, access_token_api),
    access_token_renewal_allowed = 
      proplists:get_value(access_token_renewal_allowed, Args, false),
    authorization_url = AuthorizationURL,
    callback_url = CallbackURL,
    consumer_key = get_mandatory_value(Args, consumer_key),
    consumer_secret = get_mandatory_value(Args, consumer_secret),
    debug_output = proplists:get_value(debug_output, Args, []),
    nonce_server = get_mandatory_value(Args, nonce_server),
    private_key = PrivateKey,
    request_token_api = get_mandatory_value(Args, request_token_api),
    signature_method = SignatureMethod
  }.


%
% Create a client in a specific state InitialState. Args is the same as in the
% call to new/1.
new(Args, InitialState, Params) ->
  set_state(new(Args), InitialState, Params).

%%

set_opaque(State, Opaque) ->
  State#state{ opaque = Opaque }.

%%

reinstantiate(Args, StateDump) ->
  update_state(new(Args), StateDump).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Internal functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

get_mandatory_value(KVs, Key) ->
  case proplists:get_value(Key, KVs) of
    undefined ->
      error_logger:error_msg("~s: Mandatory parameter '~s' is undefined~n",
        [?MODULE, Key]
      ),
      erlang:error({undefined_param, Key});

    Value -> Value
  end.

%%

get_mandatory_values(KVs, Keys) ->
  [get_mandatory_value(KVs, K) || K <- Keys].

%%

prepare_request_params(StateData, ExtraOAuthParams, AppParams, SignData) ->
  {Ts, N} = nonce:get_ts_nonce(StateData#state.nonce_server),

  LTs = integer_to_list(Ts),
  OAuthParams = ExtraOAuthParams ++ [
    {"oauth_consumer_key", StateData#state.consumer_key},
    {"oauth_timestamp", LTs},
    {"oauth_nonce", LTs ++ N},
    {"oauth_version", "1.0"}
  ],

  {ok, SignMethod, Signature, _DebugInfo} = oauth:generate_signature(
    StateData#state.signature_method,
    [
      {consumer_secret, StateData#state.consumer_secret},
      {params, OAuthParams ++ AppParams},
      {private_key, StateData#state.private_key}
    ] ++ SignData
  ),

  SignatureParams = [
    {"oauth_signature_method", SignMethod},
    {"oauth_signature", Signature}
  ],

  ContentType = "application/x-www-urlencoded",

  {ContentType, AllEncodedParams} = oauth:encode_parameters(
    AppParams ++ OAuthParams ++ SignatureParams
  ),

  {ContentType, AppEncodedParams} = oauth:encode_parameters(AppParams),

  {
    ContentType,
    AllEncodedParams,
    AppEncodedParams,
    OAuthParams ++ SignatureParams
  }.

%%

handle_response(StateData, Response, ErrorState, ErrorMonadFuns) ->

  ReportError = fun(Details) ->
    {error,
      {
        StateData#state{ state = ErrorState },
        {error, Details}
      }
    }
  end,
  
  error_monad:do(
    [
      fun(R) ->
        case R of
          % The default is to return 'full result': see http(3), search for 
          % 'full_result'.
          {ok, Result} -> Result;
          {error, _} = Error -> ReportError(Error)
        end
      end,

      fun({StatusLine, _Headers, Body} = R) ->
        case StatusLine of
          {"HTTP/1.1", 200, "OK"} -> oauth:decode_parameters(Body);
          _ -> ReportError({invalid_http_response, R})
        end
      end,

      fun(Params) ->
        case proplists:get_value("oauth_token", Params) of
          undefined -> ReportError({missing_response_parameter, oauth_token});
          OAuthToken -> {Params, OAuthToken}
        end
      end,

      fun({Params, OAuthToken}) ->
        case proplists:get_value("oauth_token_secret", Params) of
          undefined ->
            ReportError({missing_response_parameter, oauth_token_secret});

          OAuthTokenSecret -> {Params, OAuthToken, OAuthTokenSecret}
        end
      end
    ] ++ ErrorMonadFuns,
    Response
  ).

%%

create_endpoint_param(HttpMethod, URL) ->
  {Scheme, _Credentials, Authority, Port, Path, _Query} = http_uri:parse(URL),

  {endpoint,
    {atom_to_list(HttpMethod), atom_to_list(Scheme), Authority, Port, Path}}.

%%

http_request(State, Method, URL, ContentType, Body, Headers) ->
  Request = case Method of
    get -> {URL ++ "?" ++ Body, Headers};
    post -> {URL, Headers, ContentType, Body}
  end,

  case lists:member(http_requests, State#state.debug_output) of
    true ->
      io:format("~nOAuth client HTTP Request:~n~s ~p~n", [Method, Request]);
    _ -> ok
  end,

  http:request(Method, Request, [], []).

%%

set_state(State, have_access_token, Params) ->
  set_state_and_tokens(State, have_access_token, Params);

set_state(State, have_request_token, Params) ->
  set_state_and_tokens(State, have_request_token, Params).

%%

set_state_and_tokens(State, NewState, Params) ->
  [Token, TokenSecret] = get_mandatory_values(Params, [token, token_secret]),

  State#state{
    state = NewState,
    token = Token,
    token_secret = TokenSecret
  }.

%%

update_state(State,
  {
    0,  % format version number
    Opaque,
    CurState,
    Token,
    TokenSecret
  }
) -> update_state(State,
    CurState,
    Opaque,
    '1.0',
    Token,
    TokenSecret,
    undefined);

update_state(State,
  {
    1,
    Opaque,
    CurState,
    ServerVersion,
    Token,
    TokenSecret,
    Verifier
  }
) -> update_state(State,
    CurState,
    Opaque,
    ServerVersion,
    Token,
    TokenSecret,
    Verifier);

update_state(_State, Dump) ->
  erlang:error({unknown_state_dump_format, Dump}).

% This function fills all required fields, so whatever dump format we
% encounter, we have to use this one to make sure all required fields are
% filled.
update_state(State,
  CurState,
  Opaque,
  ServerVersion,
  Token,
  TokenSecret,
  Verifier
) ->
  State#state
  {
    opaque = Opaque,
    server_version = ServerVersion,
    state = CurState,
    token = Token,
    token_secret = TokenSecret,
    verifier = Verifier
  }.
