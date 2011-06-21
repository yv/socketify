Socketify
=========

Getting started:

 - run the program you want as a socket server:
   `./socketify /usr/bin/perl -npe 'tr/m-za-l/a-z/'`
 - run the `test_client.py` script with the input file
   (or just open a socket and write to it in your program)
   `python test_client.py README.md`

Why would this be more useful than inetd or similar programs?

socketify runs the program until it first reads from stdin and
forks off the server at this point, whereas inetd would always
start the program from the beginning. This makes a difference
whenever the startup time of the program is significant.

Does it always work?

Right now, the inserted client code only exists for x86, which means that
you can socketify 32-bit programs, but not 64-bit programs, on
a 64-bit Linux. Programs that do more complex things than reading
from stdin and writing to stdout may get confused.
