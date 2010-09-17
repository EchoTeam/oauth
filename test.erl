-module(test).
-compile(export_all).

run() ->
  [application:start(X) || X <- [crypto, inets, ssl]],

  {ok, Nonce} = nonce:start_link(),

  {ok, [Info]} = public_key:pem_to_der("./test_rsa"),
  {ok, PrivateKey} = public_key:decode_private_key(Info),

  BaseURL = "http://tiger.xiolabs.com:9006/api",

  [
    begin
      C = oauthclient:new([
        {access_token_api, {post, BaseURL ++ "/AccessToken"}},
        {authorization_url,
          {BaseURL ++ "/Authorize", [tXXXoken_optional, cXXXallback_optional],
            []}},
        {callback_url, "http://consumer.example.org/authorized?a=b"},
        {nonce_server, Nonce},
        {consumer_key, "dpf43f3p2l4k3l03"},
        {consumer_secret, "kd94hf93k423kf44"},
        {private_key, PrivateKey},
        {request_token_api, {post, BaseURL ++ "/RequestToken"}},
        {signature_method, SignMethod}
      ]),

      AppParams = [
        {"b", "1"},
        {"a", "2"},
        {"a", "1"},
        {"and this", "one is @#$%^ cool"}
      ],

      {C2, {ok, _}} = oauthclient:get_request_token(C, AppParams),
      {C3, {ok, AuthorizationURL}} = oauthclient:mk_authorization_url(C2),

      io:format("~s~n", [AuthorizationURL]),

      {C4, {ok, _}} = oauthclient:get_access_token(C3),

      AccessURL = BaseURL ++ "/Access",

      {_C5, {ok, {URL, Headers, ContentType, Body}}} =
        oauthclient:mk_access_request(
          C4, post, with_rest, AccessURL, [{"k", "v"}, {"x", "y"}]
        ),

      Response = http:request(post, {URL, Headers, ContentType, Body}, [], []),

      io:format("Response (~s): ~p~n", [SignMethod, Response])
    end
    || SignMethod <- [plaintext, hmac_sha1, rsa_sha1]
  ],

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
    {consumer_key, "vss.73rus.com"},
    {consumer_secret, "Y6c+cbDHNLpZCW5FGU0UyAKQ"},
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

state_dump() ->
  [application:start(X) || X <- [crypto, inets, ssl]],

  [
    begin
      C = oauthclient:reinstantiate(
        termie_config(SignatureMethod), binary_to_term(Dump)
      ),

      R = termie_make_request(C, "http://term.ie/oauth/example/echo_api.php",
        [{"method", atom_to_list(SignatureMethod)}]),

      io:format("state_dump: ~p~n", [R])
    end
    || {Dump, SignatureMethod} <-
    [
      {
        <<131,104,5,97,0,100,0,9,117,110,100,101,102,105,110,101,
        100,100,0,17,104,97,118,101,95,97,99,99,101,115,115,95,
        116,111,107,101,110,107,0,9,97,99,99,101,115,115,107,
        101,121,107,0,12,97,99,99,101,115,115,115,101,99,114,
        101,116>>,
        hmac_sha1
      },

      {
        <<131,104,5,97,0,100,0,9,117,110,100,101,102,105,110,101,
        100,100,0,17,104,97,118,101,95,97,99,99,101,115,115,95,
        116,111,107,101,110,107,0,9,97,99,99,101,115,115,107,
        101,121,107,0,12,97,99,99,101,115,115,115,101,99,114,
        101,116>>,
        plaintext
      }
    ]
  ].

%%

thread_state(Seed, SeedF, []) -> SeedF(Seed);
thread_state(Seed, SeedF, [F|Funs]) ->
  {ok, NewSeed} = F(Seed),
  case NewSeed of
    done -> ok;
    NS -> thread_state(SeedF(NS), SeedF, Funs)
  end.
