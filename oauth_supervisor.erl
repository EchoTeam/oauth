%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

-module(oauth_supervisor).
-behaviour(supervisor).
-export([start_link/0, init/1]).

start_link() ->
    supervisor:start_link(?MODULE, none).

init(none) ->
    {ok, {{one_for_one, 10, 10},
        [{nonce, {nonce, start_link, []},
		permanent, 10000, worker, [nonce]}
        ]}}.
