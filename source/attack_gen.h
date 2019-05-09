/* RIPE was originally developed by John Wilander (@johnwilander)
 * and was debugged and extended by Nick Nikiforakis (@nicknikiforakis)
 *
 * Released under the MIT license (see file named LICENSE)
 *
 * The 64b port of RIPE was developed by Hubert ROSIER.
 *
 * This program is part the paper titled
 * RIPE: Runtime Intrusion Prevention Evaluator
 * Authored by: John Wilander, Nick Nikiforakis, Yves Younan,
 *              Mariam Kamkar and Wouter Joosen
 * Published in the proceedings of ACSAC 2011, Orlando, Florida
 *
 * Please cite accordingly.
 */

/**
 * @author John Wilander
 * 2007-01-16
 */
/** EDITED
 * @author Hubert ROSIER
 * 2019-04
 */

#ifndef ATTACK_GEN_H
#define ATTACK_GEN_H

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <setjmp.h>
#include <fcntl.h>

#include "parameters.h"

typedef int boolean;
enum booleans {FALSE=0, TRUE};

typedef struct attack_form ATTACK_FORM;
struct attack_form {
  enum techniques technique;
  enum inject_params inject_param;
  enum code_ptrs code_ptr;
  enum locations location;
  enum functions function;
};

typedef struct char_payload CHARPAYLOAD;
struct char_payload {
  enum inject_params inject_param;
  size_t size;
  void *overflow_ptr;  /* Points to code pointer (direct attack) */
                       /* or general pointer (indirect attack)   */
  char *buffer;

  jmp_buf *jmp_buffer;
  void *old_base_ptr;  // used to mangle the overflow pointer
  char *stack_buffer;  // used for r2libc and rop attack on jmp_buf

  uintptr_t buffer_addr;  // used to set the address of the fake stack frame
  size_t offset_to_fake_return_addr;
  void *fake_return_addr;
  uintptr_t ptr_to_correct_return_addr;
};

struct attackme{
    char buffer[256];
    int (*func_ptr)(const char *);
};

/**
 * main
 * -t technique
 * -i injection parameter
 * -c code pointer
 * -l memory location
 * -f function to overflow with
 * -d output debug info (set to 't' for TRUE)
 */
int main(int argc, char **argv);

void perform_attack(
    int (*stack_func_ptr_param)(const char *),
    jmp_buf stack_jmp_buffer_param
    );

boolean build_payload(CHARPAYLOAD *payload);

boolean is_terminating_char(char value);
boolean contains_terminating_char(uintptr_t value);
void remove_nulls(char *contents, size_t length);
void locate_terminating_chars(char *contents, size_t length);

void set_technique(char *choice);
void set_inject_param(char *choice);
void set_code_ptr(char *choice);
void set_location(char *choice);
void set_function(char *choice);

int dummy_function(const char *str) {
  return 0;
}

boolean is_attack_possible();
boolean are_variables_well_located(uintptr_t buffer, uintptr_t target_addr, uintptr_t overflow_ptr);
void homebrew_memcpy(void *dst, const void *src, size_t len);

int  find_gadget_offset(char* search_chars);
void gadget1(int a, int b);
void gadget2(int a, int b);
int  gadget3(int a, int b);
void gadget4(int a, int b);

// Inspired from the POC of CVE-2013-4788
// http://hmarco.org/bugs/CVE-2013-4788.html
#ifdef __i386__
   #define ROTATE 0x9
#elif __x86_64__
   #define ROTATE 0x11
#elif __arm__
   #define ROTATE 0x0
#else
   #error The exploit does not support this architecture
#endif

unsigned long rol(uintptr_t value) {
  return (value << ROTATE) | (value >> (__WORDSIZE - ROTATE));
}


#endif /* !ATTACK_GEN_H */
