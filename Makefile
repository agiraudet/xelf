NAME			:=	woody_woodpacker

BUILD_DIR	:=	./build

INC_DIR		:=	./inc

SRCS_DIR	:=	./src

SRCS			:=	main.c \
							cypher.c \
							inject.c \
							segc.c \
							xelf.c

SRCS_ASM	:=	payload_dyn.asm \
							payload_exec.asm

OBJS			:=	$(SRCS:%.c=$(BUILD_DIR)/%.o)

OBJS_ASM	:=	$(SRCS_ASM:%.asm=$(BUILD_DIR)/%)

HDR_ASM		:=	$(SRCS_ASM:%.asm=$(INC_DIR)/%.h)

INC_FLAGS	:=	$(addprefix -I, $(INC_DIR))

CXXFLAGS	:=	-MD -Wall -Wextra -Werror -g $(INC_FLAGS)

CXX				:=	gcc

AXXFLAGS	:=	-f bin

AXX				:=	nasm

$(NAME): $(OBJS)
	$(CXX) $(CXXFLAGS) $(OBJS) $(DEPS) -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: $(SRCS_DIR)/%.c | $(BUILD_DIR) $(HDR_ASM)
	$(CXX) $(CXXFLAGS) -c $< -o $@ 

$(BUILD_DIR)/%: $(SRCS_DIR)/%.asm | $(BUILD_DIR)
	$(AXX) $(AXXFLAGS) $< -o $@

$(INC_DIR)/%.h: $(BUILD_DIR)/%
	echo "#ifndef $(shell echo $$(basename $<) | tr '[:lower:]' '[:upper:]')_H" > $@
	echo "#define $(shell echo $$(basename $<) | tr '[:lower:]' '[:upper:]')_H" >> $@
	echo "" >> $@
	xxd -i -n $$(basename $<) $< >> $@
	echo "" >> $@
	echo "#endif // $(shell echo $$(basename $<) | tr '[:lower:]' '[:upper:]')_H" >> $@

all: $(NAME)

clean:
	rm -rf $(BUILD_DIR)

fclean: clean
	rm -f woody
	rm -f $(NAME)
	rm -f $(HDR_ASM)

re: fclean all

-include $(OBJS:.o=.d)

.PHONY: all clean fclean re
