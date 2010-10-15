%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

-module(oauthserver_app).
-behaviour(application).

-export([start/2, stop/1]).

start(_Type, _Args) ->
  {ok, DocRoot} = application:get_env(doc_root),
  {ok, IP} = application:get_env(ip),
  {ok, {Mod, InitArg}} = application:get_env(callback_module),
  {ok, Port} = application:get_env(port),
  {ok, ServerName} = application:get_env(server_name),

  error_logger:info_msg(
    "Starting up ~p~n" ++
    "",
    [?MODULE]
  ),

  {ok, ModArg} = Mod:init(InitArg),

  Opaque = {callback_module, Mod, ModArg},

  yaws:start_embedded(DocRoot,
    [
      {servername, ServerName}, {listen, IP}, {port, Port},
      {appmods, [{"/api", oauthserver_api}]},
      {opaque, Opaque}
    ]
  ),

  oauthserver_sup:start_link().

stop(_State) ->
  yaws:stop().

