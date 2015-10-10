LIBS=../lib/libmaatframe.so -lMESA_handle_logger  -lMESA_htable -lrulescan -lpcre -lpthread
INC=-I../inc/ -I/usr/include/MESA/
all:
	g++ -o maat_test -g -Wall maat_test.cpp $(INC) $(LIBS)
clean:
	rm maat_test test.log* -f
