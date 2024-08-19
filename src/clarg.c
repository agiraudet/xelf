#include "clarg.h"
#include <stdio.h>
#include <stdlib.h>

static int ft_strcmp(const char *s1, const char *s2) {
  int i;
  i = 0;
  while (s1[i] && s1[i] == s2[i])
    i++;
  return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}

static int ft_strncmp(const char *s1, const char *s2, size_t n) {
  size_t i;
  i = 0;
  if (!n)
    return (0);
  while ((s1[i] && s1[i] == s2[i]) && i < n - 1)
    i++;
  return ((unsigned char)s1[i] - (unsigned char)s2[i]);
}

static char *ft_strchr(const char *s, int c) {
  while (*s && *s != c)
    s++;
  if (*s != c)
    s = 0;
  return ((char *)s);
}

static void *ft_memset(void *s, int c, size_t n) {
  unsigned char *cursor;
  cursor = s;
  while (n-- > 0)
    *cursor++ = c;
  return (s);
}

static t_cla *get_cla() {
  static t_cla cla;
  return &cla;
}

static int cla_vector_init(t_cla_vector *vec, size_t capacity) {
  vec->size = 0;
  vec->capacity = capacity;
  if (capacity == 0)
    return vec->data = NULL, 0;
  else
    vec->data = (const char **)calloc(capacity, sizeof(char *));
  return 0;
}

static int cla_vector_pushback(t_cla_vector *vec, const char *str) {
  if (!vec)
    return -1;
  if (vec->size >= vec->capacity) {
    if (vec->capacity == 0)
      vec->capacity = 1;
    else
      vec->capacity *= 2;
    vec->data =
        (const char **)realloc(vec->data, vec->capacity * sizeof(char *));
    if (!vec->data)
      return -1;
  }
  vec->data[vec->size++] = str;
  return 0;
}

static const char *cla_vector_at(t_cla_vector *vec, size_t index) {
  if (!vec || index >= vec->size)
    return NULL;
  return vec->data[index];
}

static bool cla_vector_in(t_cla_vector *vec, const char *str) {
  for (size_t i = 0; i < vec->size; i++) {
    if (ft_strcmp(vec->data[i], str) == 0)
      return true;
  }
  return false;
}

// static const char *cla_vector_popfront(t_cla_vector *vec) {
//   if (!vec || vec->size == 0)
//     return NULL;
//   const char *str = vec->data[0];
//   for (size_t i = 0; i < vec->size - 1; i++) {
//     vec->data[i] = vec->data[i + 1];
//   }
//   vec->size--;
//   return str;
// }

// static bool cla_vector_empty(t_cla_vector *vec) { return vec->size == 0; }
//
// bool cla_vector_in(t_cla_vector *vec, const char *str) {
//   for (size_t i = 0; i < vec->size; i++) {
//     if (ft_strcmp(vec->data[i], str) == 0)
//       return true;
//   }
//   return false;
// }

// static const char *cla_vector_popback(t_cla_vector *vec) {
//   if (!vec || vec->size == 0)
//     return NULL;
//   return vec->data[--vec->size];
// }

static void clarg_destroy(t_clarg *clarg) {
  if (!clarg)
    return;
  if (clarg->allowed_values.data)
    free(clarg->allowed_values.data);
}

static void cla_destroy(void) {
  t_cla *cla = get_cla();
  if (cla->args) {
    for (size_t i = 0; i < cla->args_count; i++)
      clarg_destroy(cla->args + i);
    free(cla->args);
  }
  if (cla->inputs.data)
    free(cla->inputs.data);
  if (cla->required_inputs.data)
    free(cla->required_inputs.data);
}

int cla_init(int argc, char **argv) {
  static bool initialized = false;
  if (initialized)
    return 0;
  t_cla *cla = get_cla();
  cla->argc = argc;
  cla->argv = argv;
  cla->args_count = 0;
  cla->args_capacity = 1;
  cla->description = NULL;
  cla->args = (t_clarg *)calloc(cla->args_capacity, sizeof(t_clarg));
  if (!cla->args) {
    return -1;
  }
  if (cla_vector_init(&cla->inputs, 1) < 0)
    return -1;
  if (cla_vector_init(&cla->required_inputs, 0) < 0)
    return -1;
  cla_arg('h', "help", "Print this help message");
  atexit(cla_destroy);
  initialized = true;
  return 0;
}

static t_clarg *clarg_init(t_clarg *clarg, char short_name,
                           const char *long_name, const char *description) {
  clarg->short_name = short_name;
  clarg->long_name = long_name;
  clarg->description = description;
  clarg->provided = false;
  clarg->value_required = false;
  clarg->value = NULL;
  ft_memset(&clarg->usage, 0, sizeof(clarg->usage));
  cla_vector_init(&clarg->allowed_values, 0);
  return clarg;
}

t_clarg *clarg_add_allowed_value(t_clarg *clarg, const char *value) {
  if (!clarg)
    return NULL;
  clarg->value_required = true;
  cla_vector_pushback(&clarg->allowed_values, value);
  return clarg;
}

static t_clarg *cla_new(void) {
  t_cla *cla = get_cla();
  if (cla->args_count >= cla->args_capacity) {
    cla->args_capacity *= 2;
    cla->args =
        (t_clarg *)realloc(cla->args, cla->args_capacity * sizeof(t_clarg));
    if (!cla->args)
      return NULL;
  }
  return cla->args + cla->args_count++;
}

t_clarg *cla_arg(char short_name, const char *long_name,
                 const char *description) {
  t_clarg *clarg = cla_get(short_name);
  if (clarg)
    return NULL;
  return clarg_init(cla_new(), short_name, long_name, description);
}

static int cla_match_shortname(t_cla *cla, const char *str) {
  str++;
  while (*str) {
    bool found = false;
    for (size_t i = 0; !found && i < cla->args_count; i++) {
      if (*str == cla->args[i].short_name) {
        t_clarg *clarg = cla->args + i;
        clarg->provided = true;
        if (clarg->value_required) {
          if (cla->i + 1 >= cla->argc) {
            fprintf(stderr, "Option -%c requires an argument\n", *str);
            return -1;
          }
          clarg->value = cla->argv[cla->i + 1];
          cla->i++;
        }
        found = true;
      }
    }
    if (!found) {
      fprintf(stderr, "Unknown option: -%c\n", *str);
      return -1;
    }
    str++;
  }
  return 0;
}

static int cla_match_longname(t_cla *cla, const char *str) {
  str += 2;
  const char *equal = ft_strchr(str, '=');
  for (size_t i = 0; i < cla->args_count; i++) {
    t_clarg *clarg = cla->args + i;
    if (equal) {
      if (ft_strncmp(clarg->long_name, str, equal - str) == 0) {
        clarg->provided = true;
        clarg->value = equal + 1;
        if (clarg->allowed_values.size > 0 &&
            !cla_vector_in(&clarg->allowed_values, clarg->value)) {
          fprintf(stderr, "Invalid value for --%s: %s\n", clarg->long_name,
                  clarg->value);
          return -1;
        }

        return 0;
      }
    } else {
      if (ft_strcmp(clarg->long_name, str) == 0) {
        clarg->provided = true;
        if (clarg->value_required) {
          if (cla->i + 1 >= cla->argc) {
            fprintf(stderr, "Option --%s requires an argument\n", str);
            return -1;
          }
          clarg->value = cla->argv[cla->i + 1];
          cla->i++;
        }
        return 0;
      }
    }
  }
  fprintf(stderr, "Unknown option: --%s\n", str);
  return -1;
}

static int cla_check_required_inputs() {
  t_cla *cla = get_cla();
  if (cla->required_inputs.size > cla->inputs.size) {
    fprintf(stderr, "Missing required input: %s\n",
            cla_vector_at(&cla->required_inputs, cla->inputs.size));
    return -1;
  }
  for (size_t i = 0; i < cla->args_count; i++) {
    t_clarg *clarg = cla->args + i;
    if (clarg->allowed_values.size > 0 && clarg->value &&
        !cla_vector_in(&clarg->allowed_values, clarg->value)) {
      fprintf(stderr, "Invalid value for --%s: %s\n", clarg->long_name,
              clarg->value);
      return -1;
    }
  }
  return 0;
}

int cla_add_required_input(const char *input) {
  t_cla *cla = get_cla();
  return cla_vector_pushback(&cla->required_inputs, input);
}

void cla_add_description(const char *description) {
  t_cla *cla = get_cla();
  cla->description = description;
}

int cla_parse() {
  t_cla *cla = get_cla();
  cla->i = 1;
  while (cla->i < cla->argc) {
    const char *arg = cla->argv[cla->i];
    if (arg[0] && arg[0] == '-' && arg[1] != '-') {
      if (cla_match_shortname(cla, arg) < 0)
        return -1;
    } else if (arg[0] && arg[0] == '-' && arg[1] == '-') {
      if (cla_match_longname(cla, arg) < 0)
        return -1;
    } else {
      cla_vector_pushback(&cla->inputs, arg);
    }
    cla->i++;
  }
  if (cla_provided('h'))
    return 1;
  return cla_check_required_inputs();
}

t_clarg *cla_get(char short_name) {
  t_cla *cla = get_cla();
  for (size_t i = 0; i < cla->args_count; i++) {
    if (cla->args[i].short_name == short_name)
      return cla->args + i;
  }
  return NULL;
}

const char *cla_value(char short_name) {
  t_clarg *clarg = cla_get(short_name);
  if (!clarg)
    return NULL;
  return clarg->value;
}

bool cla_provided(char short_name) {
  t_clarg *clarg = cla_get(short_name);
  if (!clarg)
    return false;
  return clarg->provided;
}

static int clar_make_usage_srt(t_cla *cla) {
  int max_len = 0;
  for (size_t i = 0; i < cla->args_count; i++) {
    t_clarg *clarg = cla->args + i;
    int len = snprintf(clarg->usage, sizeof(clarg->usage), "  ");
    if (clarg->short_name) {
      len += snprintf(clarg->usage + len, sizeof(clarg->usage), "-%c",
                      clarg->short_name);
      if (clarg->value_required)
        len += snprintf(clarg->usage + len, sizeof(clarg->usage), " <option>");
      len += snprintf(clarg->usage + len, sizeof(clarg->usage), ", ");
    }
    if (clarg->long_name) {
      len += snprintf(clarg->usage + len, sizeof(clarg->usage), "--%s",
                      clarg->long_name);
      if (clarg->value_required)
        len += snprintf(clarg->usage + len, sizeof(clarg->usage), "=<option>");
    }
    if (len > max_len)
      max_len = len;
  }
  return max_len;
}

const char *cla_get_input(size_t index) {
  t_cla *cla = get_cla();
  if (index >= cla->inputs.size)
    return NULL;
  return cla_vector_at(&cla->inputs, index);
}

void cla_usage() {
  t_cla *cla = get_cla();
  if (cla->description)
    printf("%s\n", cla->description);
  printf("Usage: %s", cla->argv[0]);
  if (cla->args_count > 0) {
    printf(" [OPTIONS] ");
    if (cla->required_inputs.size > 0) {
      for (size_t i = 0; i < cla->required_inputs.size; i++)
        printf("%s ", cla_vector_at(&cla->required_inputs, i));
    }
    printf("\nOptions:");
  }
  printf("\n");
  int max_len = clar_make_usage_srt(cla);
  for (size_t i = 0; i < cla->args_count; i++) {
    int written = printf("%s", cla->args[i].usage);
    printf("%*s %s\n", max_len - written, "", cla->args[i].description);
  }
}

void clarg_debug_print(t_clarg *clarg) {
  printf("--------------\n");
  printf("short_name: %c\n", clarg->short_name);
  printf("long_name: %s\n", clarg->long_name);
  printf("description: %s\n", clarg->description);
  printf("provided: %d\n", clarg->provided);
  printf("value_required: %d\n", clarg->value_required);
  printf("value: %s\n", clarg->value);
  printf("allowed_values: ");
  for (size_t i = 0; i < clarg->allowed_values.size; i++) {
    printf("%s, ", clarg->allowed_values.data[i]);
  }
  if (clarg->allowed_values.size > 0)
    printf("\n");
  else
    printf("Any\n");
}

void cla_debug_print() {
  t_cla *cla = get_cla();
  printf("argc: %d\n", cla->argc);
  if (cla->inputs.size > 0) {
    printf("inputs:");
    for (size_t i = 0; i < cla->inputs.size; i++) {
      if (i > 0)
        printf(",");
      printf(" %s", cla_vector_at(&cla->inputs, i));
    }
    printf("\n");
  }
  for (size_t i = 0; i < cla->args_count; i++) {
    clarg_debug_print(cla->args + i);
  }
}
