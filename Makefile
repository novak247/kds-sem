# Compiler and flags
CC = clang
CFLAGS = -Wall -Wextra -Wpedantic -g
LDFLAGS = -lcrypto -lz

# Target executable names
CLIENT = client
RECEIVER = receiver

# Source files
CLIENT_SRC = client.c
RECEIVER_SRC = receiver.c

# Build all targets
all: $(CLIENT) $(RECEIVER)

# Build the client
$(CLIENT): $(CLIENT_SRC)
	$(CC) $(CFLAGS) -o $(CLIENT) $(CLIENT_SRC) $(LDFLAGS)

# Build the receiver
$(RECEIVER): $(RECEIVER_SRC)
	$(CC) $(CFLAGS) -o $(RECEIVER) $(RECEIVER_SRC) $(LDFLAGS)

# Clean up generated files
clean:
	rm -f $(CLIENT) $(RECEIVER)
