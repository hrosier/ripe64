#!/usr/bin/python
# Updated version of program developed by Hubert ROSIER
# to assist the automated testing using the 64b port of the RIPE evaluation tool
#
# RIPE was originally developed by John Wilander (@johnwilander)
# and was debugged and extended by Nick Nikiforakis (@nicknikiforakis)
#
# Released under the MIT license (see file named LICENSE)
#
# The original program is part the paper titled
# RIPE: Runtime Intrusion Prevention Evaluator
# Authored by: John Wilander, Nick Nikiforakis, Yves Younan,
#              Mariam Kamkar and Wouter Joosen
# Published in the proceedings of ACSAC 2011, Orlando, Florida
#
# Please cite accordingly.

import os
import sys
from sets import Set

compilers = ["gcc", "clang"]

locations = ["stack","heap","bss","data"]

code_ptr = [
 "ret","baseptr",
 "funcptrstackvar", "funcptrstackparam",
 "funcptrheap", "funcptrbss", "funcptrdata",
 "structfuncptrstack", "structfuncptrheap",
 "structfuncptrbss", "structfuncptrdata",
 "longjmpstackvar", "longjmpstackparam",
 "longjmpheap", "longjmpbss", "longjmpdata"
]

attacks = [
 # "nonop","simplenop",
 "simplenopequival", "r2libc", "rop"]

funcs = [
    "memcpy", "strcpy", "strncpy", "sprintf", "snprintf",
    "strcat", "strncat", "sscanf", "fscanf", "homebrew"
  ]

techniques = []
repeat_times = 0
results = {}
print_OK = True
print_SOME = True
print_FAIL = True
summary_format = "bash"

if len(sys.argv) < 2:
  print("Usage: python "+sys.argv[0] + "[direct|indirect|both] <number of times to repeat each test>")
  sys.exit(1)
else:
  if sys.argv[1] == "both":
    techniques = ["direct","indirect"]
  else:
    techniques = [sys.argv[1]]

  repeat_times = int(sys.argv[2])

  if len(sys.argv) > 3:
    if sys.argv[3] in ["gcc","clang"]:
      compilers = [sys.argv[3]]
    i = 4
    while (i<len(sys.argv)):
      arg = sys.argv[i]
      if ("only" in arg or "not" in arg):
        if arg == "--only-summary":
          print_OK = False
          print_SOME = False
          print_FAIL = False
        elif arg == "--not-ok":
          print_OK = False
        elif arg == "--only-ok":
          print_SOME = False
          print_FAIL = False
        elif arg == "--not-fail":
          print_FAIL = False
        elif arg == "--only-fail":
          print_OK = False
          print_SOME = False
        elif arg == "--only-some":
          print_OK = False
          print_FAIL = False
      elif "format" in arg:
        summary_format = arg
      i+=1

# Colored text
def colored_string(string, color, size=0):
    padding = ' '*(size-len(string)) if size else ''
    return color+string+'\033[0m'+padding
def red(string, size=0):
    return colored_string(string, '\033[91m', size)
def green(string, size=0):
    return colored_string(string, '\033[92m', size)
def orange(string, size=0):
    return colored_string(string, '\033[93m', size)
def blue(string, size=0):
    return colored_string(string, '\033[94m', size)
def bold(string, size=0):
    return colored_string(string, '\033[1m', size)
def underline(string, size=0):
    return colored_string(string, '\033[4m', size)

def analyze_log(log_entry, additional_info):
  if log_entry.find("jump buffer is between") != -1:
    additional_info += [orange('SpecialPayload')]

  if log_entry.find("Overflow pointer contains terminating char") != -1:
    additional_info += [orange("TermCharInOverflowPtr")]

  # Terminating chars in middle of the payload
  if log_entry.find("in the middle") != -1:
    additional_info += [orange('TermCharInPayload')]

  if log_entry.find("Unknown choice of") != -1:
    additional_info += [red('UnknownChoice')]

  if log_entry.find("Could not build payload") != -1:
    additional_info += [red('BuildPayloadFailed')]

  if log_entry.find("find_gadget") != -1:
    additional_info += [red('FindGadgetFail')]

  if log_entry.find("Unable to allocate heap") != -1:
    additional_info += [red('HeapAlloc')]

  if log_entry.find("the wrong order") != -1:
    additional_info += [red('HeapAllocOrder')]

  if log_entry.find("Target address is lower") != -1:
    additional_info += [red('Underflow')]

  # Defenses log
  if log_entry.find("AddressSanitizer") != -1:
    additional_info += [red('ASAN')]

  return additional_info

def analyze_log2(additional_info):
  i = 0
  while i < repeat_times:
    i += 1
    log_entry2 = open("/tmp/ripe_log2"+str(i),'r').read()
    if log_entry2.find("Segmentation fault") != -1:
      additional_info += [red('SEGFAULT')]
    elif log_entry2.find("Bus error") != -1:
      additional_info += [red('BUSERROR')]
    elif log_entry2.find("Illegal instruction") != -1:
      additional_info += [red('SIGILL')]
    # elif log_entry2.find("I/O error") != -1:
    # it is a 'normal' error when no shell has been spawned

  return additional_info

if not os.path.exists("/tmp/ripe-eval"):
  os.system("mkdir /tmp/ripe-eval")

for compiler in compilers:
  total_ok = 0
  total_fail = 0
  total_some = 0
  total_np = 0
  for tech in techniques:
    for loc in locations:
      for ptr in code_ptr:
        for attack in attacks:
          for func in funcs:
            i = 0
            s_attempts = 0
            attack_possible = 1
            additional_info = [];
            while i < repeat_times:
              i += 1

              os.system("rm /tmp/ripe_log")
              parameters = (tech,loc,ptr,attack,func)
              parameters_str = "-t %8s -l %5s -c %18s -i %16s -f %8s" % parameters
              sys.stdout.write('... Running %s ...\r' % parameters_str)
              sys.stdout.flush()
              os.system("echo "+parameters_str+">> /tmp/ripe_log")
              ## Valgrind - Memcheck
              # cmdline = "(echo \"touch /tmp/ripe-eval/f_xxxx\" | G_SLICE=always-malloc G_DEBUG=gc-friendly  valgrind -v --tool=memcheck --num-callers=40 ./build/"+compiler+"_attack_gen "+parameters_str+" >> /tmp/ripe_log 2>&1) 2> /tmp/ripe_log2"+str(i)
              ## Dr. Memory
              # cmdline = "(echo \"touch /tmp/ripe-eval/f_xxxx\" | drmemory -no_check_uninitialized -crash_at_error -- ./build/"+compiler+"_attack_gen "+parameters_str+" >> /tmp/ripe_log 2>&1) 2> /tmp/ripe_log2"+str(i)

              cmdline = "(echo \"touch /tmp/ripe-eval/f_xxxx\" | ./build/"+compiler+"_attack_gen "+parameters_str+" >> /tmp/ripe_log 2>&1) 2> /tmp/ripe_log2"+str(i)
              os.system(cmdline)

              log_entry = open("/tmp/ripe_log","r").read()
              if log_entry.find("Impossible") != -1:
                # print("%5s %s %6s" % (compiler,parameters_str,blue("NOT POSSIBLE")))
                attack_possible = 0
                break  #Not possible once, not possible always

              additional_info = analyze_log(log_entry, additional_info)

              if os.path.exists("/tmp/ripe-eval/f_xxxx"):
                s_attempts += 1
                os.system("rm /tmp/ripe-eval/f_xxxx")

            if attack_possible == 0:
              total_np += 1
              continue

            # SUCCESS
            if s_attempts == repeat_times:
              if print_OK:
                print("%5s %s %s (%s/%s) %s" % (compiler,parameters_str,
                    green("OK", 4),
                    s_attempts,repeat_times,
                    ' '.join(Set(additional_info))))
              total_ok += 1
            # FAIL
            elif s_attempts == 0:
              additional_info = analyze_log2(additional_info)
              if print_FAIL:
                print("%5s %s %6s (%s/%s) %s" % (compiler, parameters_str,
                     red("FAIL", 4),
                     s_attempts, repeat_times,
                     ' '.join(Set(additional_info))))
              total_fail += 1
            # SOME
            else:
              if print_SOME:
                additional_info = analyze_log2(additional_info)
                print("%5s %s %6s (%s/%s) %s" % (compiler,parameters_str,
                    orange("SOME", 4),
                    s_attempts,repeat_times,
                    ' '.join(Set(additional_info))))
              total_some += 1


  results[compiler] = {
          'total_ok': total_ok,
          'total_fail': total_fail,
          'total_some': total_some,
          'total_np': total_np}

total_attacks = total_ok + total_some + total_fail + total_np
if "bash" in summary_format:
  for compiler in results:
    print("\n"+bold("||Summary "+compiler+"||"))
    total_attacks = results[compiler]["total_ok"] + results[compiler]["total_some"] + results[compiler]["total_fail"]
    print("OK: %s SOME: %s FAIL: %s NP: %s Total Attacks: %s\n\n"% (
      results[compiler]["total_ok"], results[compiler]["total_some"], results[compiler]["total_fail"],
      results[compiler]["total_np"], total_attacks))

if "latex" in summary_format:
  print("\\begin{tabular}{|c|c|c|c|}\\hline\n"
    "\\thead{Setup} & \\thead{Functional \\\\ attacks} & \\thead{Partly functional \\\\ attacks} & \\thead{Nonfunctional \\\\ attacks}\\\\\\hline\\hline\n")
  for compiler in results:
    print(" (%s) & %s (%s\\%%) & %s (%s\\%%) & %s (%s\\%%) \\\\ \\hline\n"% (
      compiler,
      results[compiler]["total_ok"], int(round((100.0*results[compiler]["total_ok"])/ total_attacks)),
      results[compiler]["total_some"], int(round((100.0*results[compiler]["total_some"])/ total_attacks)),
      results[compiler]["total_fail"], int(round((100.0*results[compiler]["total_fail"])/ total_attacks))
      ))
  print("\\end{tabular}\n")



