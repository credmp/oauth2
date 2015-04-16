-module(oauth2_jwt_token_tests).

-include_lib("proper/include/proper.hrl").
-include_lib("eunit/include/eunit.hrl").

%%%===================================================================
%%% Test cases
%%%===================================================================

proper_type_spec_test_() ->
    {timeout, 1200, [{?LINE,
                      fun() -> proper:check_specs(oauth2_jwt_token,
                                                  [{to_file, user}]) end}]}.

