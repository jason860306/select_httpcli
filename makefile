CXX=g++

CUR_DIR = $(PWD)
PROJ_DIR=$(CUR_DIR)
OUTPUT_DIR = $(PROJ_DIR)

INCLUDE=
LIBS=
SHARED=-shared
FPIC=-fPIC
MACRO=
CFLAGS=-g -W -Wall -O0 ${MACRO}

OBJECT=$(patsubst %.cpp,%.o,$(wildcard $(PROJ_DIR)/*.cpp))
BIN=$(OUTPUT_DIR)/httpcli2

$(shell mkdir -p ${OUTPUT_DIR})

RM=@rm -fr

.PHONE: all clean test
all:$ $(BIN)

$(BIN):$(OBJECT)
	@echo compiling $@
	$(CXX) $(CFLAGS) $(INCLUDE) $(LIBS) $^ -o $@

$(OBJECT):
	@echo compiling $(@:%.o=%.cpp)
	$(CXX) -c $(INCLUDE) $(CFLAGS) $(@:%.o=%.cpp) -o $@

clean:
	$(RM) $(OBJECT)
	$(RM) $(BIN)
	$(RM) *~

test:
	@echo "CUR_DIR=" $(CUR_DIR)
	@echo "OUTPUT_DIR=" $(OUTPUT_DIR)
	@echo "INCLUDE=" $(INCLUDE)
	@echo "OBJECT=" $(OBJECT)
	@echo "BIN=" $(BIN)
