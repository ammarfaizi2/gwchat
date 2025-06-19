
CXXFLAGS = -Wall -Wextra -Os -std=c++20 -ggdb3
CFLAGS = -Wall -Wextra -Os -ggdb3
LDFLAGS = -Os -ggdb3
LIBS = -lpthread

all: gwchat

gwchat.o: gwchat.c
hash_table.o: hash_table.cc
OBJECTS = gwchat.o hash_table.o

gwchat: $(OBJECTS)
	$(CXX) $(LDFLAGS) -o $@ $^ $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

%.o: %.cc
	$(CXX) $(CXXFLAGS) -c $< -o $@

clean:
	rm -f gwchat *.o

.PHONY: all clean
