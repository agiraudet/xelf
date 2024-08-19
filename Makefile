NAME			:=	xelf

HELLO			:= hello

BUILD_DIR	:=	build

INC_DIR		:=	inc

SRCS_DIR	:=	src

PLD_DIR		:=	$(SRCS_DIR)/payloads

SRCS			:=	clarg.c \
							xelf.c \
							payload.c \
							main.c

PLD_SRCS	:=	$(wildcard $(PLD_DIR)/*.asm)

OBJS			:=	$(SRCS:%.c=$(BUILD_DIR)/%.o)

OBJS_ASM	:=	$(PLD_SRCS:%.asm=$(BUILD_DIR)/%)

HDR_ASM		:=	$(PLD_SRCS:$(PLD_DIR)/%.asm=$(INC_DIR)/payloads/%.h)

INC_FLAGS	:=	$(addprefix -I, $(INC_DIR)) $(addprefix -I, $(INC_DIR)/payloads)

CXXFLAGS	:=	-MD -Wall -Wextra -Werror -g $(INC_FLAGS)

CXX				:=	gcc

AXXFLAGS	:=	-f bin

AXX				:=	nasm

$(NAME): $(OBJS) $(HDR_ASM)
	$(CXX) $(CXXFLAGS) $(OBJS) -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRCS_DIR)/%.c | $(BUILD_DIR) $(HDR_ASM)
	$(CXX) $(CXXFLAGS) -c $< -o $@ 

$(BUILD_DIR)/%: $(PLD_DIR)/%.asm | $(BUILD_DIR)
	$(AXX) $(AXXFLAGS) $< -o $@

$(INC_DIR)/payloads/%.h: $(BUILD_DIR)/%
	echo "#ifndef $(shell echo $$(basename $<) | tr '[:lower:]' '[:upper:]')_H" > $@
	echo "#define $(shell echo $$(basename $<) | tr '[:lower:]' '[:upper:]')_H" >> $@
	echo "" >> $@
	xxd -i -n $$(basename $<) $< >> $@
	echo "" >> $@
	echo "#endif // $(shell echo $$(basename $<) | tr '[:lower:]' '[:upper:]')_H" >> $@

$(HELLO):
	echo -e '#include <unistd.h>\nint main(){write(1,"Hello World!\\n",13);return 0;}' | $(CXX) -xc - -o $(HELLO)


all: $(NAME)

clean:
	rm -rf $(BUILD_DIR)
	rm -f hello.c

fclean: clean
	rm -f $(NAME)
	rm -f $(HDR_ASM)
	rm -f $(HELLO)
	rm -f woody

re: fclean all

-include $(OBJS:.o=.d)

.PHONY: all clean fclean re
