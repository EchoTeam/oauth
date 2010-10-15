%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

-module(oauthserver_api).
-export([out/1]).

-include_lib("/usr/local/lib/yaws/include/yaws_api.hrl").

out(A) ->
  URLPath = A#arg.appmoddata,
  Request = A#arg.req,
  Headers = A#arg.headers,
  {callback_module, Mod, ModArg} = A#arg.opaque,

  Url = yaws_api:request_url(A),
  Scheme = Url#url.scheme,

  %
  % XXX: not tested with SSL
  %
  % It was suggested[1] to use inets:sockname() or ssl:sockname(), but the
  % former is not available in R12B2.
  %
  % [1]: http://article.gmane.org/gmane.comp.web.server.yaws.general/1904
  %
  {ok, Port} = inet:port(A#arg.clisock),

  error_monad:do([
    fun(_) ->
      ensure_http_method(Mod, ModArg, Request#http_request.method,
        ['GET', 'POST'])
    end,

    fun(Method) -> atom_to_list(Method) end,

    fun(Method) ->
      PortStr = integer_to_list(Port),

      case string:tokens(Headers#headers.host, ":") of
        [ Hostname ] -> {Method, Hostname};
        [ Hostname, PortStr ] -> {Method, Hostname};

        % Apparently we can receive a request with 'Host: hostname:port' header
        % where 'port' is different from the port we are listening on.
        [ _, _ ] ->
          {error, Mod:render_error(ModArg, invalid_port_number_in_host_header,
              Headers#headers.host)};

        _ ->
          {error,
            Mod:render_error(ModArg, invalid_host_header, Headers#headers.host)
          }
      end
    end,
        
    fun({Method, Hostname}) ->
      Endpoint = {Method, Scheme, Hostname, Port, A#arg.server_path},

      case string:tokens(URLPath, "/") of
        [ "Access" ] -> access_resource(A, Mod, ModArg, Endpoint);
        [ "AccessToken" ] -> access_token(A, Mod, ModArg, Endpoint);
        [ "Authorize" ] -> authorize(A, Mod, ModArg);
        [ "RequestToken" ] -> request_token(A, Mod, ModArg, Endpoint);
        _ ->
          error_logger:info_msg("Invalid API method URL: '~s'~n", [URLPath]),
          {error, 
            Mod:render_error(ModArg, invalid_api_method, URLPath)
          }
      end
    end
    ],
    nothing
  ).

%%

check_signature(
  "HMAC-SHA1" = SignMethod, Signature, Params, _TokenOption, ConsumerSecret,
  TokenSecret, Endpoint
) ->
  {ok, SignMethod, ExpectedSignature, _DebugInfo} =
    oauth:generate_signature(hmac_sha1, [
      {consumer_secret, ConsumerSecret},
      {endpoint, Endpoint},
      {params, [
        {K, V} || {K, V} <- Params,
            K =/= "oauth_signature_method",
            K =/= "oauth_signature"
      ]},
      {token_secret, TokenSecret}
    ]),

  if
    Signature == ExpectedSignature -> ok;
    true -> {error, invalid_signature, [
      {expected, ExpectedSignature}, 
      {received, Signature}
      ]}
  end;

check_signature(
  "PLAINTEXT" = SignMethod, EncodedSignature, _Params, TokenOption,
  ExpectedConsumerSecret, ExpectedTokenSecret, _Endpoint
) ->
  %
  % NB! Per http://oauth.net/core/1.0/#anchor22 (section 9.4.1), consumer and
  % token secrets within the signature are *double*-encoded:
  %
  % oauth_signature=encode(encode(CSecret) ++ "&" ++ encode(TSecret))
  %
  % ...and this is the parameter *value*, which needs to be encoded once again
  % per section 5.1.
  %
  % At this point the caller has already decoded the parameter value (e.g. the
  % outermost 'encode()'), but we still have to decode the signature and
  % secrets.
  %

  Signature = oauth:percent_decode(EncodedSignature),

  Values =
    case [oauth:percent_decode(X) || X <- string:tokens(Signature, "&")] of
      [X] -> [X, ""];
      X -> X
    end,

  ExpectedValues = [
    ExpectedConsumerSecret,
    case TokenOption of
      token_required -> ExpectedTokenSecret;
      token_unexpected -> ""
    end
  ],

  if
    Values == ExpectedValues -> ok;

    true ->
      error_logger:error_msg("Invalid ~s signature: '~s'~n",
        [SignMethod, Signature]
      ),

      {error, invalid_signature, [
        {expected_values, ExpectedValues}
      ]}
  end;

check_signature(
  SignMethod, _Signature, _Params, _TokenOption, _ConsumerSecret, _TokenSecret,
  _Endpoint
) ->
  error_logger:error_msg("Unsupported signature method: ~s~n", [SignMethod]),
  {error, unsupported_signature_method, SignMethod}.

%%

%%

request_token(A, Mod, ModArg, Endpoint) ->
  handle_request(A, Mod, ModArg, token_unexpected, Endpoint,
    [
      fun(BodyKVs) ->
        issue_token("request",
          fun() ->
            % XXX: this is double work, since we've already extracted the
            % consumer key as part of handle_request (when checking the
            % signature), and this is why we are asserting that this key/value
            % pair must be present. However it's a necessary evil to keep the
            % framework generic enough.
            ConsumerKey = proplists:get_value("oauth_consumer_key", BodyKVs),

            Mod:issue_request_token(ModArg, ConsumerKey, BodyKVs)
          end
        )
      end
    ]
  ).

%%

ensure_http_method(Mod, ModArg, Actual, Allowed) ->
  case lists:member(Actual, Allowed) of
    false ->
      AcceptedMethods = string:join([atom_to_list(X) || X <- Allowed], ", "),

      error_logger:error_msg("Invalid method: ~s (accepted: ~s)~n",
        [Actual, AcceptedMethods]
      ),

      {
        error,
        Mod:render_error(ModArg, invalid_http_method,
          {Actual, AcceptedMethods})
      };

    true -> Actual
  end.

%%

get_required_parameter(Mod, ModArg, BodyKVs, Par) ->
  case proplists:get_value(Par, BodyKVs) of
    undefined ->
      error_logger:error_msg("'~s' not specified in request parameters: ~p~n",
        [Par, BodyKVs]
      ),

      {error, Mod:render_error(ModArg, missing_required_parameter, Par)};

    Value -> {ok, Value}
  end.

%%

authorize(A, Mod, ModArg) ->
  Request = A#arg.req,

  error_monad:do(
    [
      fun(_) ->
        ensure_http_method(Mod, ModArg, Request#http_request.method, ['GET'])
      end,

      fun(_) ->
        case A#arg.querydata of
          undefined -> [];
          QueryString -> oauth:decode_parameters(QueryString)
        end
      end
    ]

    ++ ensure_oauth_params_unique_ErrorMonadFuns(Mod, ModArg)

    ++ [
      fun(Params) ->
        case get_required_parameter(Mod, ModArg, Params, "oauth_token") of
          {ok, Token} ->
            Callback = proplists:get_value("oauth_callback", Params),
            authorize_token_callback(Mod, ModArg, A, Token, Callback, Params);
          Error -> Error
        end
      end
    ],
    nothing
  ).

%%

authorize_token_callback(Mod, ModArg, A, Token, Callback, Params) ->
  CallbackAction = case Callback of
    undefined -> undefined;
    _ ->
      {"application/x-www-urlencoded", TokenParam} =
        oauth:encode_parameters([{"oauth_token", Token}]),

      % We don't want to *really* parse the URL here: it might look invalid to
      % Erlang's http_uri:parse but be acceptable by the consumer. So we'll
      % stick to a simple heuristic here to see if there is query part in the
      % provided URL.
      {redirect,
        Callback ++
        case string:chr(Callback, $?) of
          0 -> "?";
          _ -> "&"
        end
        ++ TokenParam
      }
  end,

  Mod:authorize_token(ModArg, A, Token, Params, CallbackAction).

%%

access_token(A, Mod, ModArg, Endpoint) ->
  handle_request(A, Mod, ModArg, token_required, Endpoint,
    [
      fun(Params) ->
        case lists:sort([K || {K,_} <- Params, K =/= "oauth_version"]) of
          [
            "oauth_consumer_key",
            "oauth_nonce",
            "oauth_signature",
            "oauth_signature_method",
            "oauth_timestamp",
            "oauth_token"
          ] -> Params;

          _ -> 
            {error,
              Mod:render_error(ModArg, access_token_extra_parameters, unused)
            }
        end
      end,

      fun(Params) ->
        ensure_parameters_present(Mod, ModArg, Params,
          ["oauth_consumer_key", "oauth_token"])
      end,

      fun({_Params, [ConsumerKey, RequestToken], unused}) ->
        issue_token(
          "access",
          fun() -> 
            Mod:issue_access_token(ModArg, ConsumerKey, RequestToken)
          end
        )
      end
    ]
  ).

%%

handle_request(A, Mod, ModArg, TokenOption, Endpoint, ErrorMonadFuns) ->
  Request = A#arg.req,

  error_monad:do(
    [
      fun(_) ->
        ensure_http_method(Mod, ModArg, Request#http_request.method,
          ['GET', 'POST'])
      end,

      fun(_) ->
        Body = case Request#http_request.method of
          'GET' ->
            case A#arg.querydata of
              undefined -> [];
              _ -> A#arg.querydata
            end;

          'POST' -> binary_to_list(A#arg.clidata)
        end,

        oauth:decode_parameters(Body)
      end,

      fun(BodyKVs) ->
        ensure_parameters_present(Mod, ModArg, BodyKVs,
          ["oauth_consumer_key", "oauth_signature_method", "oauth_signature"])
      end
    ]

    ++ case TokenOption of
        token_required -> [
          fun({BodyKVs, Values, unused}) ->
            ensure_parameters_present(Mod, ModArg, BodyKVs, ["oauth_token"],
              Values)
          end,

          fun({BodyKVs, [Token], [ConsumerKey | _] = Values}) ->
            case Mod:get_token_secret(ModArg, ConsumerKey, Token) of
              {ok, TokenSecret} ->
                {BodyKVs, Values, TokenSecret};

              _ ->
                error_logger:error_msg(
                  "Unknown token secret: consumer_key='~s' token='~s'~n",
                    [ConsumerKey, Token]
                ),

                {error, Mod:render_error(ModArg, invalid_token, Token)}
            end
          end
        ];

        token_unexpected -> [
          fun({BodyKVs, Values, unused}) -> {BodyKVs, Values, ""} end
        ]
    end

    ++ [
      fun({BodyKVs, [ConsumerKey, SignMethod, Signature], TokenSecret}) ->
        {BodyKVs, SignMethod, Signature, ConsumerKey, TokenSecret}
      end,

      fun({BodyKVs, SignMethod, Signature, ConsumerKey, TokenSecret}) ->
        case Mod:get_consumer_secret(ModArg, ConsumerKey) of
          {ok, ConsumerSecret} ->
            {BodyKVs, SignMethod, Signature, ConsumerSecret, TokenSecret};

          _ ->
            error_logger:error_msg(
              "Unknown consumer key '~s'~n", [ConsumerKey]
            ),

            {error,
              Mod:render_error(ModArg, invalid_consumer_key, ConsumerKey)
            }
        end
      end,

      fun({BodyKVs, SignMethod, Signature, ConsumerSecret, TokenSecret}) ->
        case
          check_signature(string:to_upper(SignMethod), Signature, BodyKVs,
            TokenOption, ConsumerSecret, TokenSecret, Endpoint)
        of
          {error, Reason, Details} ->
            error_logger:error_msg("Signature check failed (~p: ~p)~n",
              [Reason, Details]
            ),

            {error, Mod:render_error(ModArg, invalid_signature, unused)};

          ok -> BodyKVs
        end
      end
    ] 
    
    ++ ensure_oauth_params_unique_ErrorMonadFuns(Mod, ModArg)
    ++ check_ts_nonce_ErrorMonadFuns(Mod, ModArg)
    ++ ErrorMonadFuns,
    nothing
  ).

%%

issue_token(Type, Fun) ->
  case Fun() of
    {ok, Token, TokenSecret, ExtraParams} ->
      {ContentType, Body} = oauth:encode_parameters([
        {"oauth_token", Token},
        {"oauth_token_secret", TokenSecret}
      ] ++ ExtraParams),

      {content, ContentType, Body};

    {error, Reason, RetVal} ->
      error_logger:error_msg("Error issuing ~s token: ~p~n", [Type, Reason]),
      {error, RetVal}
  end.

%%

access_resource(A, Mod, ModArg, Endpoint) ->
  handle_request(A, Mod, ModArg, token_required, Endpoint,
    [
      fun(Params) ->
        ensure_parameters_present(Mod, ModArg, Params, ["oauth_token"])
      end,

      fun({Params, [AccessToken], unused}) ->
        Mod:access_resource(ModArg, AccessToken, Params)
      end
    ]
  ).

%%

check_ts_nonce_ErrorMonadFuns(Mod, ModArg) ->
  [
    fun(Params) ->
      ensure_parameters_present(Mod, ModArg, Params,
        ["oauth_consumer_key", "oauth_nonce", "oauth_timestamp"]
      )
    end,

    fun({Params, [ConsumerKey, Nonce, Timestamp], unused}) ->
      case Mod:saw_ts_nonce(ModArg, ConsumerKey, Timestamp, Nonce) of
        {true, Reason, RetVal} ->
          error_logger:error_msg("Timestamp/Nonce check failed: ~p~n",
            [Reason]),
          RetVal;

        _ -> Params
      end
    end
  ].

%%

ensure_oauth_params_unique_ErrorMonadFuns(Mod, ModArg) ->
  [
    fun(Params) ->
      case dups_exist(
          lists:sort([K || {[$o, $a, $u, $t, $h, $_ | _] = K, _} <- Params])
        ) of
        
        {true, K} ->
          {error, Mod:render_error(ModArg, duplicate_parameter, K)};

        _ -> Params
      end
    end
  ].

%%

% NB! The list is assumed to be sorted!
dups_exist([]) -> false;
dups_exist([_]) -> false;
dups_exist([X, X | _]) -> {true, X};
dups_exist([_, X | T]) -> dups_exist([X | T]).

%%

ensure_parameters_present(Mod, ModArg, KVs, Keys) ->
  ensure_parameters_present(Mod, ModArg, KVs, Keys, unused).

ensure_parameters_present(Mod, ModArg, KVs, Keys, Extra) ->
  oauth:ensure_parameters_present(KVs, Keys, Extra,
    fun(P, K) -> get_required_parameter(Mod, ModArg, P, K) end
  ).
