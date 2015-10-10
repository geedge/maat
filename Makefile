#opt: OPTFLAGS = -O2
#export OPTFLAGS

.PHONY: all clean opt

all:
	cd src/entry/ && $(MAKE)
	cd test && $(MAKE)
clean:
	cd src/entry/ && $(MAKE) clean
	cd test && $(MAKE) clean
			 
opt:
	$(MAKE) all
