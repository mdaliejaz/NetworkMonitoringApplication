all: mydump

mydump: mydump.c
	@echo "Generating mydump executable"
	gcc -w mydump.c -lpcap -o mydump

clean:
	@echo "Cleaning mydump executable"
	rm -f mydump
