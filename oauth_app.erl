%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

-module(oauth_app).
-behavior(application).
-export([start/0, start/2, stop/1]).

stop(_) -> ok.

start() -> application:start(?MODULE).

start(_Type, _Args) ->
	oauth_supervisor:start_link().
