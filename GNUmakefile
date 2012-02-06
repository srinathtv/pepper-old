#
# This makefile system follows the structuring conventions
# recommended by Peter Miller in his excellent paper:
#
#	Recursive Make Considered Harmful
#	http://aegis.sourceforge.net/auug97.pdf
#
OBJDIR := obj
BINDIR := bin

TOP = .

# try to infer the correct GCCPREFIX
ifndef GCCPREFIX
GCCPREFIX := 
endif

CC	:= $(GCCPREFIX)gcc -pipe
CPP	:= $(GCCPREFIX)g++ -pipe
AS	:= $(GCCPREFIX)as
AR	:= $(GCCPREFIX)ar
LD	:= $(GCCPREFIX)ld
OBJCOPY	:= $(GCCPREFIX)objcopy
OBJDUMP	:= $(GCCPREFIX)objdump
NM	:= $(GCCPREFIX)nm

# Native commands
NCC	:= gcc $(CC_VER) -pipe
TAR	:= gtar
PERL	:= perl
PYTHON := python

CHECKER := $(PYTHON) cpplint.py --verbose 5 

# Compiler flags
CFLAGS := $(CFLAGS) -I$(TOP) -MD 
CFLAGS += -Wall -Wno-format -Wno-unused -gstabs -fopenmp -O3

# Add -fno-stack-protector if the option exists.
CFLAGS += $(shell $(CC) -fno-stack-protector -E -x c /dev/null >/dev/null 2>&1 && echo -fno-stack-protector)  

# Common linker flags
LDFLAGS := -L/usr/local/lib -lm -lgmp -lfcgi -lgomp -lcurl -lpapi

# common include flags
IFLAGS := -I/usr/include -I/usr/local/include -pthread

# Add sfs flags
LDFLAGS += -L/usr/local/lib/sfslite-1.2 -lsfscrypt -lasync -lresolv -L/usr/local/lib/chacha -lchacha
IFLAGS += -I/usr/local/include/sfslite-1.2 -I/usr/local/include/chacha

GCC_LIB := $(shell $(CC) $(CFLAGS) -print-libgcc-file-name)

# Lists that the */Makefrag makefile fragments will add to
OBJDIRS :=

# Make sure that 'all' is the first target
all:

# Eliminate default suffix rules
.SUFFIXES:

# Delete target files if there is an error (or make is interrupted)
.DELETE_ON_ERROR:

# make it so that no intermediate .o files are ever deleted
.PRECIOUS: %.o

# Set to nothing (i.e., V = ) to enable verbose outputs.
V = @

# Include Makefrags for subdirectories
include common/Makefrag
include crypto/Makefrag
include libv/Makefrag
include apps/Makefrag

APPS_BINS = $(patsubst apps/%.cpp, $(BINDIR)/%, $(APPS_SRCFILES))
COMMON_LIB_OBJFILES = $(COMMON_OBJFILES) $(CRYPTO_OBJFILES) $(LIBV_OBJFILES)

# How to build apps
$(APPS_BINS) : $(BINDIR)/% : $(OBJDIR)/$(SRCDIR)/%.o $(COMMON_LIB_OBJFILES)
	@mkdir -p $(@D)
	@echo + mk $@
	$(V)$(CPP) $(CFLAGS) $(IFLAGS) -o $@ $^ $(LDFLAGS)

# Provers also need prover objfile.
$(patsubst %, $(BINDIR)/%_p, $(COMPUTATION_APPS)): $(PROVER_OBJFILES)

# Verifiers also need verifier objfile.
$(patsubst %, $(BINDIR)/%_v, $(COMPUTATION_APPS)): $(VERIFIER_OBJFILES)

all: $(APPS_BINS)

computation_state:
	mkdir -p $@

run-%: $(BINDIR)/%_v $(BINDIR)/%_p computation_state
	rm -rf computation_state/*
	./run/$*.sh $(ARGS)

# For deleting the build
clean:
	rm -rf $(OBJDIR) $(BINDIR) computation_state/*

# This magic automatically generates makefile dependencies
# for header files included from C source files we compile,
# and keeps those dependencies up-to-date every time we recompile.
# See 'mergedep.pl' for more information.
$(OBJDIR)/.deps: $(foreach dir, $(OBJDIRS), $(wildcard $(OBJDIR)/$(dir)/*.d))
	@mkdir -p $(@D)
	@$(PERL) mergedep.pl $@ $^

-include $(OBJDIR)/.deps

always: 
	@:

.PHONY: always
