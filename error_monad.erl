-module(error_monad).
-export([
  break/1,
  do/1,
  do/2,
  error/1,
  error/2,
  error/3,
  ok/1
]).

% Poor man's Error monad.
do(F) -> do(F, undefined).

do([], Arg) -> Arg;

do([Fun | RestFuns], Arg) ->
  case Fun(Arg) of
    {error, Error} -> Error;
    {break, Data} -> Data;
    {success, V} -> do(RestFuns, V);
    V -> do(RestFuns, V)
  end.

% "Fail" functions. The application will see {error, A, B, ...} value extracted
% out of the monad.
error(A) -> {error, {error, A}}.
error(A, B) -> {error, {error, A, B}}.
error(A, B, C) -> {error, {error, A, B, C}}.

% "Success" function. No interruption. The next function gets A.
ok(A) -> {success, A}.

% "Interrupts" functions. 
break(A) -> {break, A}.
