

all: sqlite3.o
	g++ -o sql -std=c++17 sql.cpp sqlite_files/sqlite3.o -lpthread -ldl

sqlite3.o:
	gcc -o sqlite_files/sqlite3.o -c sqlite_files/sqlite3.c