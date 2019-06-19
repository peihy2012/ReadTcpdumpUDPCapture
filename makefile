IDIR = ../include

# CC = gcc
CXX = g++ -g -Wall -std=c++11

CFLAGS = -I$(IDIR)

TARGET = ReadTcpdumpCapture

ODIR = obj
LDIR = ../lib

LIBS = 

# _DEPS = hellomake.h
_DEPS = 
DEPS = $(patsubst %,$(IDIR)/%,$(_DEPS))

# _OBJ = hellomake.o hellofunc.o 
_OBJ = ReadTcpdumpCapture.o
OBJ = $(patsubst %,$(ODIR)/%,$(_OBJ))

$(TARGET): $(OBJ)
	$(CXX) -o $@ $^ $(CFLAGS) $(LIBS)

$(ODIR)/%.o: %.cc $(DEPS)
	$(CXX) -c -o $@ $< $(CFLAGS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~ $(TARGET)
