#opt: OPTFLAGS = -O2
#export OPTFLAGS

CC		= gcc
CCC		= g++
CFLAGS		= -Wall -g -fPIC
CFLAGS		+= $(OPTFLAGS)
LDDICTATOR	= -Wl,-wrap,malloc -Wl,-wrap,calloc -Wl,-wrap,free -Wl,-wrap,realloc
LDFLAGS		= -lMESA_handle_logger -lMESA_htable -lpthread -lm -lrulescan -lpcre -lMESA_field_stat
#LDFLAGS		+= $(LDDICTATOR)
MAILLIB = ../lib

G_H_DIR			=../inc_internal
H_DIR			=-I$(G_H_DIR) -I../../inc
LIBMAAT = libmaatframe.a
LIBMAAT_SO = libmaatframe.so 

OBJS=config_monitor.o Maat_rule.o Maat_api.o Maat_stat.o UniversalBoolMatch.o dynamic_array.o cJSON.o\
	json2iris.o map_str2int.o interval_index.o great_index_engine.o mesa_fuzzy.o
.c.o:
	$(CC) -c $(CFLAGS) -I. $(H_DIR) $<

.cpp.o:
	$(CCC) -c $(CFLAGS) -I. $(H_DIR) $<

all: $(LIBMAAT) $(LIBMAAT_SO)

$(LIBMAAT_SO): $(OBJS)
	$(CCC) -o $(LIBMAAT_SO) -shared $(OBJS) $(LDFLAGS)
	cp $(LIBMAAT_SO) ../../lib/
$(LIBMAAT): $(OBJS)
	echo  making dynamic lib ...
	ar cqs $(LIBMAAT) $(OBJS)
	cp $(LIBMAAT) ../../lib/

clean:
	rm -rf *.o $(LIBMAAT) *~

opt:
	$(MAKE) all
