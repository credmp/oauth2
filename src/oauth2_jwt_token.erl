%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Copyright (c) 2015 Arjen Wiersma
%%%
%%% Permission to use, copy, modify, and/or distribute this software for any
%%% purpose with or without fee is hereby granted, provided that the above
%%% copyright notice and this permission notice appear in all copies.
%%%
%%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
%%%
%%% @doc JWT specification
%%% @end
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

%%%_* Module declaration ===============================================
-module(oauth2_jwt_token).

-behaviour(oauth2_token_generation).

%%%_* Exports ==========================================================
%%%_ * API -------------------------------------------------------------
-export([generate/1]).

%%%_* Code =============================================================
%%%_ * API -------------------------------------------------------------
%% @doc Generates a random OAuth2 token.
-spec generate(oauth2:context()) -> oauth2:token().
generate(Context) -> 
    Header = create_header(Context),
    Payload = create_payload(Context),
    Token = create_token(Context, Header, Payload),
    Token.

-spec create_header(oauth2:context()) -> binary().
create_header(_Context) ->
    base64url:encode(jiffy:encode({[{alg, <<"HS512">>},{typ, <<"JWT">>}]})).

-spec create_payload(oauth2:context()) -> binary().
create_payload(Context) ->
    Issued = oauth2:seconds_since_epoch(0),
    Expiry = case oauth2:get(Context, <<"expiry_time">>) of
		 {ok, Value} -> Value;
		 {error, notfound} -> oauth2:seconds_since_epoch(3600)
	     end,
    Doc = {[{exp, Expiry}, {iat, Issued}, {name, <<"Arjen Wiersma">>}]},
    Json = jiffy:encode(Doc),
    base64url:encode(Json).

-spec create_token(oauth2:context(), binary(), binary()) -> binary().
create_token(_Context, Header, Payload) ->
    Packet = <<Header/binary, ".", Payload/binary>>,
    Signature = base64url:encode(hmac:hmac512("secret", Packet)),
    <<Packet/binary, ".", Signature/binary>>.
