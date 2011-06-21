all: socketify

socketify: socketify.c vars.c
	gcc -static -o socketify socketify.c
	strip socketify

vars.c: codebits2.S mkcode.py
	as -a --listing-cont-lines=100 | python mkcode.py > vars.c
