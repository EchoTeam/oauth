%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

%
% Demo OAuth server-side bookkeeping
%

-module(bookkeeper).
-behaviour(gen_server).

-export([
  % public API
  start_link/0,

  % gen_server callbacks
  code_change/3,
  handle_call/3,
  handle_cast/2,
  handle_info/2,
  init/1,
  terminate/2
]).

-record(state, { consumers = [], next_token = 0, token_table, ts_nonce_table}).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Public API
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

start_link() ->
  gen_server:start_link(?MODULE, args, []).


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% gen_server callbacks
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

%%

handle_call({authorize_token, Token}, _From, State) ->
  ets:update_element(State#state.token_table, Token, {2, authorized_token}),
  {reply, ok, State};

handle_call({check_ts_nonce, ConsumerKey, Timestamp, Nonce}, _From, State) ->
  CurTNs =
    case ets:lookup(State#state.ts_nonce_table, ConsumerKey) of
      [{ConsumerKey, X}] -> X;
      _ -> {0, []}
    end,

  {LastTs, LastNonces} = CurTNs,

  {Response, NewTNs} = if
    Timestamp < LastTs ->
      {
        {error, invalid_timestamp,
          [{status, 400}, {html, "Invalid timestamp"}]},
        CurTNs
      };

    Timestamp == LastTs ->
      case lists:member(Nonce, LastNonces) of
        true ->
          {
            {error, used_nonce,
              [{status, 400}, {html, "Nonce value already used"}]},
            CurTNs
          };

        false ->
          {
            ok,
            {LastTs, [Nonce | LastNonces]}
          }
      end;

    Timestamp > LastTs ->
      {
        ok,
        {Timestamp, [Nonce]}
      }
  end,

  ets:insert(State#state.ts_nonce_table, {ConsumerKey, NewTNs}),
  {reply, Response, State};

handle_call({deny_token, Token}, _From, State) ->
  ets:update_element(State#state.token_table, Token, {2, unauthorized_token}),
  {reply, ok, State};

handle_call({get_consumer_secret, ConsumerKey}, _From, State) ->
  {reply, get_consumer_secret(State, ConsumerKey), State};

handle_call({get_token_info, Token}, _From, State) ->
  {
    reply,
    case ets:lookup(State#state.token_table, Token) of
      [{Token, Type, _Secret, ConsumerKey, Data}] ->
        {Type, ConsumerKey, Data};

      _ -> not_found
    end,
    State
  };

handle_call({get_token_secret, ConsumerKey, Token}, _From, State) ->
  {
    reply,
    case ets:lookup(State#state.token_table, Token) of
      [{Token, _, TokenSecret, ConsumerKey, _}] -> {ok, TokenSecret};
      _ -> not_found
    end,
    State
  };

handle_call({issue_request_token, ConsumerKey, Resource}, _From, State) ->
  case get_consumer_secret(State, ConsumerKey) of
    not_found -> {reply, {error, invalid_consumer_key}, State};

    {ok, ConsumerSecret} ->
      {NextToken, Token, TokenSecret} = issue_token(State, ConsumerSecret),

      Row = {Token, request_token, TokenSecret, ConsumerKey, Resource},

      io:format("XXX: issued ~p~n", [Row]),

      ets:insert(State#state.token_table, Row),

      {
        reply,
        {ok, Token, TokenSecret, []},
        State#state{ next_token = NextToken }
      }
  end;

handle_call({promote_token, Token}, _From, State) ->
  [{Token, TokenType, _TokenSecret, ConsumerKey, Resource}] =
    ets:lookup(State#state.token_table, Token),

  case TokenType of
    authorized_token ->
      {ok, ConsumerSecret} = get_consumer_secret(State, ConsumerKey),

      {NextToken, AccessToken, AccessTokenSecret} =
        issue_token(State, ConsumerSecret),

      % XXX: add expiration to the access token

      Row =
        {AccessToken, access_token, AccessTokenSecret, ConsumerKey, Resource},

      ets:insert(State#state.token_table, Row),
      ets:delete(State#state.token_table, Token),

      io:format("XXX: '~s' exchanged authorized request token '~s' for " ++
        "access token '~s'~n", [ConsumerKey, Token, AccessToken]),

      {
        reply,
        {ok, AccessToken, AccessTokenSecret},
        State#state{ next_token = NextToken}
      };

    _ ->
      {
        reply,
        {error, {invalid_token_type, TokenType}},
        State
      }
  end;

handle_call(_Request, _From, State) ->
  {noreply, State}.


handle_cast(_Request, State) ->
  {noreply, State}.


handle_info(_Request, State) ->
  {noreply, State}.


init(_Args) ->
  {
    ok,
    #state{
      consumers = [{"consumer_key", "consumer_secret"}],
      token_table = ets:new(token_table, [set, private]),
      ts_nonce_table = ets:new(token_table, [set, private])
    }
  }.

%%

terminate(_Reason, _State) ->
  ok.


%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Internal functions
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

get_consumer_secret(State, ConsumerKey) ->
  case proplists:get_value(ConsumerKey, State#state.consumers) of
    undefined -> not_found;
    Secret -> {ok, Secret}
  end.

%%

generate_token_secret(Secret) ->
  base64:encode_to_string(
    erlang:md5(term_to_binary({Secret, random:uniform()}))
  ).

%%

issue_token(#state{ next_token = NextToken }, Secret) ->
  {NextToken + 1, integer_to_list(NextToken), generate_token_secret(Secret)}.
