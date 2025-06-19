
COMMON_FLAGS = -Wall -Wextra -Wno-gnu -Os -ggdb3 -ffunction-sections -fdata-sections -flto -Wno-unused-function -Wno-unused-parameter
CXXFLAGS = -std=gnu++20 $(COMMON_FLAGS)
CFLAGS = -std=gnu11 $(COMMON_FLAGS)
LDFLAGS = -Os -ggdb3 -flto
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
