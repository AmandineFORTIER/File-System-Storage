

all: 
	g++ -o server -std=c++17 server.cpp -lpthread
	g++ -o tlsserver -std=c++17 tlsSever.cpp -lpthread -lsqlite3 -lzip -I/usr/local/include/botan-2 -L/usr/local/lib/  -lbotan-2
