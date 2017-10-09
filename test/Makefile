LIBS=../lib/libmaatframe.so
INC=-I../inc/ -I/usr/include/MESA/
all:
	g++ -o maat_test -g -Wall maat_test.cpp $(INC) $(LIBS) -lMESA_handle_logger
clean:
	rm maat_test test.log* -f
