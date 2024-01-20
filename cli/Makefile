.PHONY = clean

OBJECTS = main.o


wirefish: $(OBJECTS)
	clang++ -o wirefish -L../libsniff -lsniff $(OBJECTS)
	install_name_tool -change libsniff.dylib ../libsniff/libsniff.dylib wirefish

main.o: main.cpp
	clang++ -std=c++17 -g -Wall -std=c++17 -I../libsniff  -c main.cpp 

clean: 
	rm $(OBJECTS) wirefish
