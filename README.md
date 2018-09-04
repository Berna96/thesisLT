# thesisLT
Tested in Ubuntu
how to install first part:
1.download libpcap from official site e compile it
./configure && make && make install
If an error occur when loading shared object libpcap.so.1, try this:

2.compile with gcc the source file pcapevolve.c
gcc -o pcapevolve pcapevolve.c -lpcap

how to install second part:
1.install python3
2.install tkinter
3.install snort and replace local.rules and snort.conf with downloaded ones


