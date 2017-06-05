LDLIBS = -lsodium

SRCDIR = src
VPATH = $(SRCDIR)

IDIR = $(SRCDIR)
CFLAGS=-g -I $(IDIR) -Werror -Wall -Wextra -std=c99 -pedantic

ODIR=build

DEPS = $(IDIR)/shs1.h

OBJ = $(ODIR)/shs1.o $(ODIR)/test.o

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test: $(OBJ)
	cc $(LDLIBS) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o test
