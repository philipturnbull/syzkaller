#!/usr/bin/env python3
import os.path
import sys

with open("config.template") as f:
	template = f.read()

base = os.path.normpath(sys.argv[1])
num_vms = int(sys.argv[2])
with open(sys.argv[3]) as f:
	focus = f.read().split()
	focus = list(s.split(':') for s in focus)

syscalls = []
for f in focus:
	syscalls.append(f)
	
template = template.replace("$FOCUS", ", ".join(['{"name": "%s", "type": "%s"}' % (s[0], s[1]) for s in focus]))
template = template.replace("$SYSCALLS", ", ".join(['"%s"' % s[0] for s in syscalls]))
template = template.replace("$BASE", base)
template = template.replace("$NUM_VMS", str(num_vms))
template = template.replace("$NUM_FUZZING_VMS", str(num_vms - 1))

print(template)
