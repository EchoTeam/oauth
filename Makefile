YAWS_EBIN = /local/lib/yaws/ebin 

ERLCFLAGS = -W2 -I/local/lib

EMODS_COMMON = \
	error_monad \
	oauth

EMODS_CLIENT = \
	nonce \
	oauth_app \
	oauth_supervisor \
	oauthclient

ESRCS_CLIENT = ${EMODS_CLIENT:%=%.erl}
ESRCS_COMMON = ${EMODS_COMMON:%=%.erl}
EOBJS_CLIENT = ${ESRCS_CLIENT:.erl=.beam}
EOBJS_COMMON = ${ESRCS_COMMON:.erl=.beam}

EOBJS = ${EOBJS_COMMON} ${EOBJS_CLIENT}

ALL_OBJS = oauth.app ${EOBJS} test.beam

all: ${ALL_OBJS}

HARDWIRE_MODULES = perl -pe 's@MODULES@join(", ", split(/\s+/, $$ENV{MODULES}))@e;'

oauth.app: oauth.app.in
	MODULES="${EMODS_COMMON} ${EMODS_CLIENT}" \
	${HARDWIRE_MODULES} \
	< oauth.app.in > oauth.app

clean:
	rm -f ${ALL_OBJS}

.SUFFIXES: .erl .beam

.erl.beam:
	erlc $(ERLCFLAGS) -o . $<
