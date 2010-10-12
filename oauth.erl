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

-module(oauth).
-export([
  decode_parameters/1,
  encode_parameters/1,
  ensure_parameters_present/4,
  generate_signature/2,
  make_signature_base_string/3,
  percent_decode/1,
  percent_encode/1
]).

decode_parameters(URLEncodedString) ->
  [X ||
    X <- [
        case string:tokens(KV, "=") of
          [K, V] -> {percent_decode(K), percent_decode(V)};
          [K] ->    {percent_decode(K), ""};
          _ ->      invalid
        end
        || KV <- string:tokens(URLEncodedString, "&")
    ],
    X =/= invalid
  ].

%%

encode_parameters(Params) ->
  {
    "application/x-www-urlencoded",
    string:join(
      [percent_encode(K) ++ "=" ++ percent_encode(V) || {K,V} <- Params], "&"
    )
  }.

%%

generate_signature(plaintext, KVPairs) ->
  error_monad:do(
    get_required_params_ErrorMonadFuns(
      KVPairs, [consumer_secret, token_secret]
    )
    ++ 
    [
      fun({_Params, [ConsumerSecret, TokenSecret]}) ->
        {ok, "PLAINTEXT",
          percent_encode(generate_signature_key(ConsumerSecret, TokenSecret)),
          []
        }
      end
    ],
    nothing
  );

generate_signature(hmac_sha1, KVPairs) ->
  generate_complex_signature("HMAC-SHA1", KVPairs,
    {
      [consumer_secret, token_secret],

      fun([ConsumerSecret, TokenSecret]) ->
        generate_signature_key(ConsumerSecret, TokenSecret)
      end
    },

    fun(BaseString, Key) ->
      crypto:sha_mac(Key, BaseString)
    end
  );

generate_signature(rsa_sha1, KVPairs) ->
  generate_complex_signature("RSA-SHA1", KVPairs,
    {
      [private_key],
      fun([PrivateKey]) -> PrivateKey end
    },

    fun(BaseString, Key) ->
      public_key:sign(list_to_binary(BaseString), Key)
    end
  ).

%%

percent_decode(X) -> percent_decode(X, []).

percent_decode([], Acc) -> lists:reverse(Acc);

percent_decode([$%, H, L | T], Acc) ->
  case hex_value(H) of
    invalid -> percent_decode([H, L | T], [$% | Acc]);
    {ok, HV} ->
      case hex_value(L) of
        invalid -> percent_decode([L | T], [H, $%, Acc]);
        {ok, LV} -> percent_decode(T, [HV * 16 + LV | Acc])
      end
  end;

percent_decode([H | T], Acc) -> percent_decode(T, [H | Acc]).

%%

%
% Encoding per
%  http://oauth.net/core/1.0/#encoding_parameters
%
percent_encode(X) -> lists:flatten(percent_encode_deep(X)).

percent_encode_deep([]) -> [];
percent_encode_deep([X | Rest]) ->
  [char_percent_encoding(X) | percent_encode_deep(Rest)].

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Internal functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

char_percent_encoding(X) when (X >= $0) andalso (X =< $9) -> X;
char_percent_encoding(X) when (X >= $a) andalso (X =< $z) -> X;
char_percent_encoding(X) when (X >= $A) andalso (X =< $Z) -> X;
char_percent_encoding($_ = X) -> X;
char_percent_encoding($. = X) -> X;
char_percent_encoding($- = X) -> X;
char_percent_encoding($~ = X) -> X;
char_percent_encoding(X) -> io_lib:format("%~.16B", [X]).
 
%%

hex_value(X) when ((X >= $0) andalso (X =< $9)) -> {ok, X - $0};
hex_value(X) when ((X >= $a) andalso (X =< $f)) -> {ok, X - $a + 10};
hex_value(X) when ((X >= $A) andalso (X =< $F)) -> {ok, X - $A + 10};
hex_value(_) -> invalid.

%%

ensure_parameters_present(Params, Keys, Extra, Accessor) ->
  Result = error_monad:do(
    [
      fun(Values) ->
        case Accessor(Params, Key) of
          {ok, Value} -> Values ++ [Value];
          Error -> {error, Error}
        end
      end
      || Key <- Keys
    ],
    []
  ),

  case Result of
    {error, _} = Error -> Error;
    _ -> {Params, Result, Extra}
  end.

%%

generate_complex_signature(SignMethod, KVPairs, {KeyGenParams, KeyGenFun}, SignatureGenFun) ->
  error_monad:do(
    get_required_params_ErrorMonadFuns(
      KVPairs, [endpoint, params] ++ KeyGenParams
    )
    ++ [
      fun({_KVPairs, [EndPoint, Params | KGParams]}) ->
        BaseString = make_signature_base_string(SignMethod, Params, EndPoint),

        Signature = SignatureGenFun(BaseString, KeyGenFun(KGParams)),


        {ok, SignMethod, base64:encode_to_string(Signature), [
          {endpoint, EndPoint},
          {basestring, BaseString}
        ]}
      end
    ],
    nothing
  ).

%%

generate_signature_key(ConsumerSecret, TokenSecret) ->
  percent_encode(ConsumerSecret) ++ "&" ++ percent_encode(TokenSecret).

%%

get_required_params_ErrorMonadFuns(KVPairs, Keys) ->
  [
    fun(_) ->
      ensure_parameters_present(KVPairs, Keys, unused,
        fun(P, K) ->
          case proplists:get_value(K, P) of
            undefined -> {error, {error, missing_parameter, K, []}};
            Value -> {ok, Value}
          end
        end
      )
    end,

    fun({PassedKVPairs, Values, unused}) -> {PassedKVPairs, Values} end
  ].

%%

make_signature_base_string(SignMethod, Params, EndPoint) ->

  {HttpMethod, Scheme, Authority, Port, Path} = EndPoint,

  Sorted = lists:sort(
    fun({A_k, A_v}, {B_k, B_v}) ->
      if
        A_k < B_k -> true;
        A_k > B_k -> false;
        true -> A_v < B_v
      end
    end,
    [
      {percent_encode(K), percent_encode(V)}
      || {K, V} <- [{"oauth_signature_method", SignMethod} | Params]
    ]
  ),

  % XXX: reuse smth
  ParString = string:join([K ++ "=" ++ V || {K, V} <- Sorted], "&"),

  SchemeLC = string:to_lower(Scheme),
  URL = SchemeLC ++ "://" ++ string:to_lower(Authority) ++ 
    (if
      ((SchemeLC == "http") andalso (Port == 80)) -> "";
      ((SchemeLC == "https") andalso (Port == 443)) -> "";
      true -> ":" ++ integer_to_list(Port)
    end)
    ++ Path,

  percent_encode(string:to_upper(HttpMethod)) ++
  "&" ++
  percent_encode(URL) ++ 
  "&" ++ 
  percent_encode(ParString).
