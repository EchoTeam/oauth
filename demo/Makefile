CONFIG = sample

YAWS_EBIN = /local/lib/yaws/ebin 

ERLCFLAGS = -W2 -I/local/lib

EMODS = \
	bookkeeper \
	client \
	demo_server

ESRCS = ${EMODS:%=%.erl}
EOBJS = ${ESRCS:.erl=.beam}

ALL_OBJS = ${EOBJS}

all: ${ALL_OBJS}

run-client: all
	erl -pa .. -eval "client:run()."

run-server: all
	erl -config $(CONFIG) -pa .. -pa $(YAWS_EBIN) -eval "ok = application:start(crypto), ok = application:start(oauthserver)."

clean:
	rm -f ${ALL_OBJS}

.SUFFIXES: .erl .beam

.erl.beam:
	erlc $(ERLCFLAGS) -o . $<
