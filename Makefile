# Compiler and flags
CC = clang
CFLAGS = -Wall -Wextra -Wpedantic -g
LDFLAGS = -lcrypto -lz

# Target executable names
SENDER = sender
RECEIVER = receiver

# Source files
SENDER_SRC = sender.c
RECEIVER_SRC = receiver.c

# Build all targets
all: $(SENDER) $(RECEIVER)

# Build the SENDER
$(SENDER): $(SENDER_SRC)
	$(CC) $(CFLAGS) -o $(SENDER) $(SENDER_SRC) $(LDFLAGS)

# Build the receiver
$(RECEIVER): $(RECEIVER_SRC)
	$(CC) $(CFLAGS) -o $(RECEIVER) $(RECEIVER_SRC) $(LDFLAGS)

# Clean up generated files
clean:
	rm -f $(SENDER) $(RECEIVER)
