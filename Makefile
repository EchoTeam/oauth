YAWS_EBIN = /local/lib/yaws/ebin 

ERLCFLAGS = -W2 -I/local/lib

EMODS_COMMON = \
	error_monad \
	oauth

# gen_oauthserver needs to be built first
EMODS_SERVER = \
	gen_oauthserver \
	dummy_server \
	oauthserver_api \
	oauthserver_app \
	oauthserver_stderr \
	oauthserver_sup

EMODS_CLIENT = \
	nonce \
	oauth_app \
	oauth_supervisor \
	oauthclient

ESRCS_SERVER = ${EMODS_SERVER:%=%.erl}
ESRCS_CLIENT = ${EMODS_CLIENT:%=%.erl}
ESRCS_COMMON = ${EMODS_COMMON:%=%.erl}
EOBJS_SERVER = ${ESRCS_SERVER:.erl=.beam}
EOBJS_CLIENT = ${ESRCS_CLIENT:.erl=.beam}
EOBJS_COMMON = ${ESRCS_COMMON:.erl=.beam}

EOBJS = ${EOBJS_COMMON} ${EOBJS_SERVER} ${EOBJS_CLIENT}

ALL_OBJS = oauth.app oauthserver.app ${EOBJS} test.beam

all: ${ALL_OBJS}

HARDWIRE_MODULES = perl -pe 's@MODULES@join(", ", split(/\s+/, $$ENV{MODULES}))@e;'

oauth.app: oauth.app.in
	MODULES="${EMODS_COMMON} ${EMODS_CLIENT}" \
	${HARDWIRE_MODULES} \
	< oauth.app.in > oauth.app

oauthserver.app: oauthserver.app.in
	MODULES="${EMODS_COMMON} ${EMODS_SERVER}" \
	${HARDWIRE_MODULES} \
	< oauthserver.app.in > oauthserver.app

run: all
	erl -pa $(YAWS_EBIN) -eval "ok = application:start(crypto), ok = application:start(oauthserver)."

clean:
	rm -f ${ALL_OBJS}

.SUFFIXES: .erl .beam

.erl.beam:
	erlc $(ERLCFLAGS) -o . $<
