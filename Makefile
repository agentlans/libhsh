# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -O2 -fPIC -Iinclude

# Directories
SRC_DIR := src
OBJ_DIR := obj
INC_DIR := include
PREFIX := /usr/local
LIB_DIR := $(PREFIX)/lib
INCLUDE_DIR := $(PREFIX)/include

# Library names
SHARED_LIB := libhsh.so
STATIC_LIB := libhsh.a

# Source and object files
SRC := $(wildcard $(SRC_DIR)/*.c)
OBJ := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRC))

# Default target
all: $(SHARED_LIB) $(STATIC_LIB)

# Create object directory if necessary
$(OBJ_DIR):
	mkdir -p $(OBJ_DIR)

# Build object files
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

# Build shared library
$(SHARED_LIB): $(OBJ)
	$(CC) -shared -o $@ $^

# Build static library
$(STATIC_LIB): $(OBJ)
	ar rcs $@ $^

# Install to system directories
install: all
	@echo "Installing libraries to $(LIB_DIR)..."
	mkdir -p $(LIB_DIR)
	cp $(SHARED_LIB) $(STATIC_LIB) $(LIB_DIR)
	@echo "Installing headers to $(INCLUDE_DIR)/hsh/..."
	mkdir -p $(INCLUDE_DIR)/hsh
	cp $(INC_DIR)/*.h $(INCLUDE_DIR)/hsh/
	@echo "Installation complete."

# Uninstall from system directories
uninstall:
	@echo "Removing installed files..."
	rm -f $(LIB_DIR)/$(SHARED_LIB) $(LIB_DIR)/$(STATIC_LIB)
	rm -rf $(INCLUDE_DIR)/hsh
	@echo "Uninstallation complete."

# Clean up build artifacts
clean:
	rm -rf $(OBJ_DIR) $(SHARED_LIB) $(STATIC_LIB)

# Phony targets
.PHONY: all clean install uninstall
