# Makefile para el password manager (C)
# Estructura esperada:
#   src/*.c   -> código fuente
#   build/    -> objetos (se crea solo)
#   pwmanager -> binario final

CC      := gcc
TARGET  := pwmanager
SRC_DIR := src
BLD_DIR := build

CFLAGS  := -std=gnu11 -Wall -Wextra -Wpedantic -Wshadow -Wconversion -O2 -MMD -MP -I$(SRC_DIR)
LDFLAGS :=
# Cuando usen libsodium, descomenten esta linea:
LDLIBS := -lsodium

SRCS := $(shell find $(SRC_DIR) -name '*.c')
OBJS := $(SRCS:$(SRC_DIR)/%.c=$(BLD_DIR)/%.o)
DEPS := $(OBJS:.o=.d)

.PHONY: all debug run clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(BLD_DIR)/%.o: $(SRC_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# make debug: sin optimizar, con simbolos y sanitizers (para cazar bugs de memoria)
debug: CFLAGS := -std=gnu11 -Wall -Wextra -Wpedantic -Wshadow -g -O0 -fsanitize=address,undefined -MMD -MP -I$(SRC_DIR) 
debug: LDFLAGS := -fsanitize=address,undefined
debug: clean $(TARGET)

run: $(TARGET)
	./$(TARGET)

clean:
	rm -rf $(BLD_DIR) $(TARGET)

-include $(DEPS)