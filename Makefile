cleanup: cyclops
	rm -rf main.o cyclops.o

cyclops: main.o cyclops.o
	g++ main.o cyclops.o -O3 -Wall -lcapstone -o cyclops

cyclops.o: cyclops.cpp
	g++ -c cyclops.cpp --std=c++17 -o cyclops.o

main.o: main.cpp
	g++ -c main.cpp --std=c++17 -o main.o
