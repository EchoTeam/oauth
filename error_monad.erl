%
% Copyright (c) 2008, 2009, 2010 JackNyfe, Inc. (dba Echo) http://aboutecho.com/
% See the accompanying LICENSE file.
%

-module(error_monad).
-export([
  do/1,
  do/2,
  error/1,
  error/2,
  error/3
]).

% Poor man's Error monad.
do(F) -> do(F, undefined).

do([], Arg) -> Arg;

do([Fun | RestFuns], Arg) ->
  case Fun(Arg) of
    {error, Error} -> Error;
    V -> do(RestFuns, V)
  end.

% "Fail" functions. The application will see {error, A, B, ...} value extracted
% out of the monad.
error(A) -> {error, {error, A}}.
error(A, B) -> {error, {error, A, B}}.
error(A, B, C) -> {error, {error, A, B, C}}.
