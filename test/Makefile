LIBS=../lib/libmaatframe.so
INC=-I../inc/ -I/usr/include/MESA/
all:
	g++ -o maat_test -g -Wall maat_test.cpp $(INC) $(LIBS)
	g++ -o digest_gen -g digest_gen.c -I../src/entry/ ../lib/libmaatframe.so 
clean:
	rm maat_test test.log* -f
