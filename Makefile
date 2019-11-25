FLAGS = -lm -O3 -Wall \
		-Wextra -Wpedantic \
		-Wimplicit-fallthrough=0 \
		-lbsd 

tests:
	gcc tests.c -g3 -o tests $(FLAGS)
	./tests
	rm tests

.PHONY: tests examples

