~~~
usage: ./flagmon [-i iface] [-r fname] [-w fname] [-vqpa] [expression]

   -i : capture interface (default: auto)
	 -r : read packets from file (default: live capture)
	 -w : write MATCHED packets to a .pcap file (default: no)
	 -p : use promiscuous mode (default: no)
	 -v : increase verbosity, can be used multiple times
	 -q : decrease verbosity, can be used multiple times
	 -a : write all packets to ./out/*.pcap files, try to dissect TCP sessions
	 last argument is an optional PCAP filter expression.
~~~