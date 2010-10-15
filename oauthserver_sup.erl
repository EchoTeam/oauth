%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

%
% oauthserver -- main supervisor
%

-module(oauthserver_sup).
-behaviour(supervisor).

-export([init/1, start_link/0]).

start_link() ->
  supervisor:start_link(?MODULE, args).

init(_) ->
  {
    ok,
    {
      {one_for_one, 1, 1},
      [
      ]
    }
  }.
