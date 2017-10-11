LIBS= -lmaatframe -lhiredis_vip
INC=-I../inc/ -I ../src/entry/ -I../src/inc_internal/ -I/usr/include/MESA/
all:
	g++ -o maat_redis_tool.o -c -g -Wall maat_redis_tool.cpp $(INC)
	g++ -o maat_redis_tool maat_redis_tool.o $(LIBS)
	g++ -o digest_gen -g digest_gen.c $(INC) $(LIBS)
clean:
	rm *.o
