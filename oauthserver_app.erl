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

