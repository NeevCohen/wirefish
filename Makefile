.PHONY = all lib cli clean

all: lib cli

lib:
	$(MAKE) -C libsniff

cli: lib
	$(MAKE) -C cli

clean:
	$(MAKE) -C cli clean
	$(MAKE) -C libsniff clean
