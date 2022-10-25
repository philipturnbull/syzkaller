// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// mutates mutates a given program and prints result.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS     = flag.String("os", runtime.GOOS, "target os")
	flagArch   = flag.String("arch", runtime.GOARCH, "target arch")
	flagSeed   = flag.Int("seed", -1, "prng seed")
	flagLen    = flag.Int("len", prog.RecommendedCalls, "number of calls in programs")
	flagEnable = flag.String("enable", "", "comma-separated list of enabled syscalls")
	flagCorpus = flag.String("corpus", "", "name of the corpus file")
)

func testMutateSchedule() {
	ts := []int{}
	newTS := []int{}

	ts = []int{0, 1, 2}
	newTS = prog.InsertThread(ts, 0, 3)
	if !reflect.DeepEqual(newTS, []int{3, 0, 1, 2}) {
		panic(fmt.Sprintf("InsertThread(0, 1): ts=%v newTS=%v\n", ts, newTS))
	}
	
	ts = []int{0, 1, 2}
	newTS = prog.InsertThread(ts, 1, 3)
	if !reflect.DeepEqual(newTS, []int{0, 3, 1, 2}) {
		panic(fmt.Sprintf("InsertThread(1, 1): ts=%v newTS=%v\n", ts, newTS))
	}
	
	ts = []int{0, 1, 2}
	newTS = prog.InsertThread(ts, 2, 3)
	if !reflect.DeepEqual(newTS, []int{0, 1, 3, 2}) {
		panic(fmt.Sprintf("InsertThread(1, 1): ts=%v newTS=%v\n", ts, newTS))
	}
	
	ts = []int{0, 1, 2}
	newTS = prog.DeleteThread(ts, 0)
	if !reflect.DeepEqual(newTS, []int{1, 2}) {
		panic(fmt.Sprintf("DeleteThread(0): ts=%v newTS=%v\n", ts, newTS))
	}
	
	ts = []int{0, 1, 2}
	newTS = prog.DeleteThread(ts, 1)
	if !reflect.DeepEqual(newTS, []int{0, 2}) {
		panic(fmt.Sprintf("DeleteThread(1): ts=%v newTS=%v\n", ts, newTS))
	}

	ts = []int{0, 1, 2}
	newTS = prog.DeleteThread(ts, 2)
	if !reflect.DeepEqual(newTS, []int{0, 1}) {
		panic(fmt.Sprintf("DeleteThread(1): ts=%v newTS=%v\n", ts, newTS))
	}

	ts = []int{0, 1}
	newTS = prog.InvertThread(ts, 0)
	if !reflect.DeepEqual(newTS, []int{1, 1}) {
		panic(fmt.Sprintf("DeleteThread(1): ts=%v newTS=%v\n", ts, newTS))
	}

	ts = []int{0, 1}
	newTS = prog.InvertThread(ts, 1)
	if !reflect.DeepEqual(newTS, []int{0, 0}) {
		panic(fmt.Sprintf("DeleteThread(1): ts=%v newTS=%v\n", ts, newTS))
	}
}
	



func main() {
	testMutateSchedule()

	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	var syscalls map[*prog.Syscall]bool
	if *flagEnable != "" {
		enabled := strings.Split(*flagEnable, ",")
		syscallsIDs, err := mgrconfig.ParseEnabledSyscalls(target, enabled, nil)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse enabled syscalls: %v\n", err)
			os.Exit(1)
		}
		syscalls = make(map[*prog.Syscall]bool)
		for _, id := range syscallsIDs {
			syscalls[target.Syscalls[id]] = true
		}
		var disabled map[*prog.Syscall]string
		syscalls, disabled = target.TransitivelyEnabledCalls(syscalls)
		for c, reason := range disabled {
			fmt.Fprintf(os.Stderr, "disabling %v: %v\n", c.Name, reason)
		}
	}
	seed := time.Now().UnixNano()
	if *flagSeed != -1 {
		seed = int64(*flagSeed)
	}
	corpus, err := db.ReadCorpus(*flagCorpus, target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read corpus: %v\n", err)
		os.Exit(1)
	}
	rs := rand.NewSource(seed)
	ct := target.BuildChoiceTable(corpus, syscalls)
	var p *prog.Prog
	if flag.NArg() == 0 {
		p = target.Generate(rs, *flagLen, ct)
	} else {
		data, err := ioutil.ReadFile(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
			os.Exit(1)
		}
		p, err = target.Deserialize(data, prog.Strict)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
			os.Exit(1)
		}
		//p.Mutate(rs, *flagLen, ct, nil, corpus)
		x := p.MutateLeaves(rs, ct, nil)
		fmt.Printf("x=%v\n", x)
	}
	fmt.Printf("%s\n", p.Serialize())
}
