#!/usr/bin/env python3
import os.path
import sys

with open("config.template") as f:
	template = f.read()

base = os.path.normpath(sys.argv[1])
num_vms = int(sys.argv[2])

template = template.replace("$BASE", base)
template = template.replace("$NUM_VMS", str(num_vms))
template = template.replace("$NUM_FUZZING_VMS", str(num_vms - 1))

print(template)
