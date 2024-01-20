.PHONY = clean

OBJECTS = sniffer.o
DYLIB = libsniff.dylib

$(DYLIB): $(OBJECTS)
	clang++ -dynamiclib $(OBJECTS) -o $(DYLIB)

sniffer.o: sniffer.cpp sniffer.h
	clang++ -g -std=c++17 -c sniffer.cpp

clean:
	rm $(OBJECTS) $(DYLIB)
