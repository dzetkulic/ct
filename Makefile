a: a.cc Makefile blake
	g++ -oa -std=c++11 -O2 -march=native -Wall a.cc blake.o -lpthread

blake: Makefile
	gcc -oblake.o -std=c11 -c -O2 -march=native -Wall ../crypto/blake2b-ref.c

