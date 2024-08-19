#ifndef CLARG_H
#define CLARG_H

#include <stdbool.h>
#include <stddef.h>

#define CLARG_MAX_USAGE_LEN 256

typedef struct {
  const char **data;
  size_t size;
  size_t capacity;
} t_cla_vector;

typedef struct {
  char short_name;
  const char *long_name;
  const char *description;
  bool provided;
  bool value_required;
  const char *value;
  t_cla_vector allowed_values;
  char usage[CLARG_MAX_USAGE_LEN];
} t_clarg;

typedef struct {
  int i;
  int argc;
  char **argv;
  t_clarg *args;
  size_t args_count;
  size_t args_capacity;
  t_cla_vector inputs;
  t_cla_vector required_inputs;
  const char *description;
} t_cla;

// BUILD
int cla_init(int argc, char **argv);
int cla_add_required_input(const char *input_name);
void cla_add_description(const char *description);
t_clarg *cla_arg(char short_name, const char *long_name,
                 const char *description);
t_clarg *clarg_add_allowed_value(t_clarg *clarg, const char *value);

// MANAGE
int cla_parse();

// INSPECT
void cla_usage();
bool cla_provided(char short_name);
t_clarg *cla_get(char short_name);
const char *cla_value(char short_name);
const char *cla_get_input(size_t index);

// DEBUG
void clarg_debug_print(t_clarg *clarg);
void cla_debug_print();

#endif // !CLARG_H
