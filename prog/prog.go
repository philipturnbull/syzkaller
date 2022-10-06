// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"reflect"

	//"github.com/google/syzkaller/pkg/log"
)

type Prog struct {
	Target   *Target
	ThreadSchedule []int
	Calls    []*Call
	Comments []string
}

// These properties are parsed and serialized according to the tag and the type
// of the corresponding fields.
// IMPORTANT: keep the exact values of "key" tag for existing props unchanged,
// otherwise the backwards compatibility would be broken.
type CallProps struct {
	FailNth int  `key:"fail_nth"`
	Async   bool `key:"async"`
	Rerun   int  `key:"rerun"`
	ThreadIndex int `key:"thread_index"`
}

type Call struct {
	Meta    *Syscall
	Args    []Arg
	Ret     *ResultArg
	Props   CallProps
	Comment string
}

func MakeCall(meta *Syscall, args []Arg) *Call {
	return &Call{
		Meta: meta,
		Args: args,
		Ret:  MakeReturnArg(meta.Ret),
	}
}

type Arg interface {
	Type() Type
	Dir() Dir
	Size() uint64

	validate(ctx *validCtx) error
	serialize(ctx *serializer)
}

type ArgCommon struct {
	ref Ref
	dir Dir
}

func (arg ArgCommon) Type() Type {
	if arg.ref == 0 {
		panic("broken type ref")
	}
	return typeRefs.Load().([]Type)[arg.ref]
}

func (arg *ArgCommon) Dir() Dir {
	return arg.dir
}

// Used for ConstType, IntType, FlagsType, LenType, ProcType and CsumType.
type ConstArg struct {
	ArgCommon
	Val uint64
}

func MakeConstArg(t Type, dir Dir, v uint64) *ConstArg {
	return &ConstArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Val: v}
}

func (arg *ConstArg) Size() uint64 {
	return arg.Type().Size()
}

// Value returns value and pid stride.
func (arg *ConstArg) Value() (uint64, uint64) {
	switch typ := (*arg).Type().(type) {
	case *IntType:
		return arg.Val, 0
	case *ConstType:
		return arg.Val, 0
	case *FlagsType:
		return arg.Val, 0
	case *LenType:
		return arg.Val, 0
	case *ResourceType:
		return arg.Val, 0
	case *CsumType:
		// Checksums are computed dynamically in executor.
		return 0, 0
	case *ProcType:
		if arg.Val == procDefaultValue {
			return 0, 0
		}
		return typ.ValuesStart + arg.Val, typ.ValuesPerProc
	default:
		panic(fmt.Sprintf("unknown ConstArg type %#v", typ))
	}
}

// Used for PtrType and VmaType.
type PointerArg struct {
	ArgCommon
	Address uint64
	VmaSize uint64 // size of the referenced region for vma args
	Res     Arg    // pointee (nil for vma)
}

func MakePointerArg(t Type, dir Dir, addr uint64, data Arg) *PointerArg {
	if data == nil {
		panic("nil pointer data arg")
	}
	return &PointerArg{
		ArgCommon: ArgCommon{ref: t.ref(), dir: DirIn}, // pointers are always in
		Address:   addr,
		Res:       data,
	}
}

func MakeVmaPointerArg(t Type, dir Dir, addr, size uint64) *PointerArg {
	if addr%1024 != 0 {
		panic("unaligned vma address")
	}
	return &PointerArg{
		ArgCommon: ArgCommon{ref: t.ref(), dir: dir},
		Address:   addr,
		VmaSize:   size,
	}
}

func MakeSpecialPointerArg(t Type, dir Dir, index uint64) *PointerArg {
	if index >= maxSpecialPointers {
		panic("bad special pointer index")
	}
	if _, ok := t.(*PtrType); ok {
		dir = DirIn // pointers are always in
	}
	return &PointerArg{
		ArgCommon: ArgCommon{ref: t.ref(), dir: dir},
		Address:   -index,
	}
}

func (arg *PointerArg) Size() uint64 {
	return arg.Type().Size()
}

func (arg *PointerArg) IsSpecial() bool {
	return arg.VmaSize == 0 && arg.Res == nil && -arg.Address < maxSpecialPointers
}

func (target *Target) PhysicalAddr(arg *PointerArg) uint64 {
	if arg.IsSpecial() {
		return target.SpecialPointers[-arg.Address]
	}
	return target.DataOffset + arg.Address
}

// Used for BufferType.
type DataArg struct {
	ArgCommon
	data []byte // for in/inout args
	size uint64 // for out Args
}

func MakeDataArg(t Type, dir Dir, data []byte) *DataArg {
	if dir == DirOut {
		panic("non-empty output data arg")
	}
	return &DataArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, data: append([]byte{}, data...)}
}

func MakeOutDataArg(t Type, dir Dir, size uint64) *DataArg {
	if dir != DirOut {
		panic("empty input data arg")
	}
	return &DataArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, size: size}
}

func (arg *DataArg) Size() uint64 {
	if len(arg.data) != 0 {
		return uint64(len(arg.data))
	}
	return arg.size
}

func (arg *DataArg) Data() []byte {
	if arg.Dir() == DirOut {
		panic("getting data of output data arg")
	}
	return arg.data
}

func (arg *DataArg) SetData(data []byte) {
	if arg.Dir() == DirOut {
		panic("setting data of output data arg")
	}
	arg.data = append([]byte{}, data...)
}

// Used for StructType and ArrayType.
// Logical group of args (struct or array).
type GroupArg struct {
	ArgCommon
	Inner []Arg
}

func MakeGroupArg(t Type, dir Dir, inner []Arg) *GroupArg {
	return &GroupArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Inner: inner}
}

func (arg *GroupArg) Size() uint64 {
	typ0 := arg.Type()
	if !typ0.Varlen() {
		return typ0.Size()
	}
	switch typ := typ0.(type) {
	case *StructType:
		var size, offset uint64
		for i, fld := range arg.Inner {
			if i == typ.OverlayField {
				offset = 0
			}
			offset += fld.Size()
			// Add dynamic alignment at the end and before the overlay part.
			if i+1 == len(arg.Inner) || i+1 == typ.OverlayField {
				if typ.AlignAttr != 0 && offset%typ.AlignAttr != 0 {
					offset += typ.AlignAttr - offset%typ.AlignAttr
				}
			}
			if size < offset {
				size = offset
			}
		}
		return size
	case *ArrayType:
		var size uint64
		for _, elem := range arg.Inner {
			size += elem.Size()
		}
		return size
	default:
		panic(fmt.Sprintf("bad group arg type %v", typ))
	}
}

func (arg *GroupArg) fixedInnerSize() bool {
	switch typ := arg.Type().(type) {
	case *StructType:
		return true
	case *ArrayType:
		return typ.Kind == ArrayRangeLen && typ.RangeBegin == typ.RangeEnd
	default:
		panic(fmt.Sprintf("bad group arg type %v", typ))
	}
}

// Used for UnionType.
type UnionArg struct {
	ArgCommon
	Option Arg
	Index  int // Index of the selected option in the union type.
}

func MakeUnionArg(t Type, dir Dir, opt Arg, index int) *UnionArg {
	return &UnionArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Option: opt, Index: index}
}

func (arg *UnionArg) Size() uint64 {
	if !arg.Type().Varlen() {
		return arg.Type().Size()
	}
	return arg.Option.Size()
}

// Used for ResourceType.
// This is the only argument that can be used as syscall return value.
// Either holds constant value or reference another ResultArg.
type ResultArg struct {
	ArgCommon
	Res   *ResultArg          // reference to arg which we use
	OpDiv uint64              // divide result (executed before OpAdd)
	OpAdd uint64              // add to result
	Val   uint64              // value used if Res is nil
	uses  map[*ResultArg]bool // args that use this arg
}

func MakeResultArg(t Type, dir Dir, r *ResultArg, v uint64) *ResultArg {
	arg := &ResultArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Res: r, Val: v}
	if r == nil {
		return arg
	}
	if r.uses == nil {
		r.uses = make(map[*ResultArg]bool)
	}
	r.uses[arg] = true
	return arg
}

func MakeReturnArg(t Type) *ResultArg {
	if t == nil {
		return nil
	}
	return &ResultArg{ArgCommon: ArgCommon{ref: t.ref(), dir: DirOut}}
}

func (arg *ResultArg) Size() uint64 {
	return arg.Type().Size()
}

// Returns inner arg for pointer args.
func InnerArg(arg Arg) Arg {
	if _, ok := arg.Type().(*PtrType); ok {
		res := arg.(*PointerArg).Res
		if res == nil {
			return nil
		}
		return InnerArg(res)
	}
	return arg // Not a pointer.
}

func isDefault(arg Arg) bool {
	return arg.Type().isDefaultArg(arg)
}

func (p *Prog) insertBefore(c *Call, calls []*Call) {
	idx := 0
	for ; idx < len(p.Calls); idx++ {
		if p.Calls[idx] == c {
			break
		}
	}
	var newCalls []*Call
	newCalls = append(newCalls, p.Calls[:idx]...)
	newCalls = append(newCalls, calls...)
	if idx < len(p.Calls) {
		newCalls = append(newCalls, p.Calls[idx])
		newCalls = append(newCalls, p.Calls[idx+1:]...)
	}
	p.Calls = newCalls
}

// replaceArg replaces arg with arg1 in a program.
func replaceArg(arg, arg1 Arg) {
	switch a := arg.(type) {
	case *ConstArg:
		*a = *arg1.(*ConstArg)
	case *ResultArg:
		replaceResultArg(a, arg1.(*ResultArg))
	case *PointerArg:
		*a = *arg1.(*PointerArg)
	case *UnionArg:
		*a = *arg1.(*UnionArg)
	case *DataArg:
		*a = *arg1.(*DataArg)
	case *GroupArg:
		a1 := arg1.(*GroupArg)
		if len(a.Inner) != len(a1.Inner) {
			panic(fmt.Sprintf("replaceArg: group fields don't match: %v/%v",
				len(a.Inner), len(a1.Inner)))
		}
		a.ArgCommon = a1.ArgCommon
		for i := range a.Inner {
			replaceArg(a.Inner[i], a1.Inner[i])
		}
	default:
		panic(fmt.Sprintf("replaceArg: bad arg kind %#v", arg))
	}
}

func replaceResultArg(arg, arg1 *ResultArg) {
	// Remove link from `a.Res` to `arg`.
	if arg.Res != nil {
		delete(arg.Res.uses, arg)
	}
	// Copy all fields from `arg1` to `arg` except for the list of args that use `arg`.
	uses := arg.uses
	*arg = *arg1
	arg.uses = uses
	// Make the link in `arg.Res` (which is now `Res` of `arg1`) to point to `arg` instead of `arg1`.
	if arg.Res != nil {
		resUses := arg.Res.uses
		delete(resUses, arg1)
		resUses[arg] = true
	}
}

// removeArg removes all references to/from arg0 from a program.
func removeArg(arg0 Arg) {
	ForeachSubArg(arg0, func(arg Arg, ctx *ArgCtx) {
		a, ok := arg.(*ResultArg)
		if !ok {
			return
		}
		if a.Res != nil {
			uses := a.Res.uses
			if !uses[a] {
				panic("broken tree")
			}
			delete(uses, a)
		}
		for arg1 := range a.uses {
			arg2 := arg1.Type().DefaultArg(arg1.Dir()).(*ResultArg)
			replaceResultArg(arg1, arg2)
		}
	})
}

// The public alias for the removeArg method.
func RemoveArg(arg Arg) {
	removeArg(arg)
}

// removeCall removes call idx from p.
func (p *Prog) RemoveCall(idx int) {
	c := p.Calls[idx]
	for _, arg := range c.Args {
		removeArg(arg)
	}
	if c.Ret != nil {
		removeArg(c.Ret)
	}
	copy(p.Calls[idx:], p.Calls[idx+1:])
	p.Calls = p.Calls[:len(p.Calls)-1]
}

func (p *Prog) CallRemovalWouldRemoveThread(idx int) bool {
	found0 := false
	found1 := false
	found2 := false

	for i, call := range p.Calls {
		if i == idx {
			continue
		}

		ti := call.Props.ThreadIndex

		if ti == 0 {
			found0 = true
		} else if ti == 1 {
			found1 = true
		} else if ti == 2 {
			found2 = true
		}
	}

	return !found0 || !found1 || !found2
}

func (p *Prog) HasAllThreads() bool {
	found0 := false
	found1 := false
	found2 := false

	for _, call := range p.Calls {
		ti := call.Props.ThreadIndex

		if ti == 0 {
			found0 = true
		} else if ti == 1 {
			found1 = true
		} else if ti == 2 {
			found2 = true
		}
	}

	return found0 && found1 && found2
}

func (p *Prog) AssignThreads() {
	if len(p.Calls) < 2 {
		return
	}

	found0 := false
	found1 := false
	found2 := false

	for _, call := range p.Calls {
		ti := call.Props.ThreadIndex

		if ti == 0 {
			found0 = true
		} else if ti == 1 {
			found1 = true
		} else if ti == 2 {
			found2 = true
		}
	}

	if found0 && found1 && found2 {
		return
	} else if !found0 {
		for _, call := range p.Calls {
			if call.Props.ThreadIndex != 0 {
				call.Props.ThreadIndex = 0
			}
		}
	} else if !found1 {
		for i := range p.Calls {
			i = len(p.Calls) - 1 - i
			if p.Calls[i].Props.ThreadIndex != 1 {
				p.Calls[i].Props.ThreadIndex = 1
			}
		}
	} else if !found2 {
		for i := range p.Calls {
			i = len(p.Calls) - 1 - i
			if p.Calls[i].Props.ThreadIndex != 2 {
				p.Calls[i].Props.ThreadIndex = 2
			}
		}

	} else {
	}

//	if !p.HasAllThreads() {
//		panic("Fixed found0 case but !p.HasAllThreads")
//	}
}

/*
func argUsesResultArg(needle *ResultArg, haystack *Arg) bool {
	switch arg := haystack.(type) {
	case *PointerArg:
		return argUsesResultArg(needle, arg.Res)
	case *GroupArg:
		for _, garg := range arg.Inner {
			if argUsesResultArg(needle, garg) {
				return true
			}
		}

		return false
	case *UnionArg:
		return argUsesResultArg(arg.Option)
	case *ResultArg:
		return arg == needle
	default:
		return false
	}
}

func threadNUsesResultArg(needle *ResultArg, n int) bool {
	//log.Logf(1, "\nAAAA looking for needle=%T/%#v in thread=%d\n", needle, needle, n)

	for _, call := range p.Calls {
		if call.Props.ThreadIndex == n {
			for _, arg := range call.Args {
				//log.Logf(1, "AAAA callIdx=%d argIdx=%d arg=%T/%#v\n", callIdx, argIdx, arg, arg)
				if argUsesResultArg(needle, arg) {
					return true
				}
			}
		}
	}

	return false
}
*/

func argUsesResultArg(arg Arg) bool {
	//log.Logf(1, "AAAA argUsesResultArg: %T -> %#v\n", arg, arg)
	switch arg := arg.(type) {
	case *PointerArg:
		return argUsesResultArg(arg.Res)
	case *GroupArg:
		for _, garg := range arg.Inner {
			if argUsesResultArg(garg) {
				return true
			}
		}

		return false
	case *UnionArg:
		return argUsesResultArg(arg.Option)
	case *ResultArg:
		return arg.Res != nil
	default:
		return false
	}
}

type resultUsage struct {
	Usage []int
}

func findOverlap(overlaps map[Arg]resultUsage, thread int, arg Arg) {
	switch arg := arg.(type) {
	case *PointerArg:
		findOverlap(overlaps, thread, arg.Res)
	case *GroupArg:
		for _, garg := range arg.Inner {
			findOverlap(overlaps, thread, garg)
		}
	case *UnionArg:
		findOverlap(overlaps, thread, arg.Option)
	case *ResultArg:
		if arg.Res != nil {
			if usage, ok := overlaps[arg.Res]; ok {
				usage.Usage[thread] += 1
				overlaps[arg.Res] = usage
			} else {
				usage = resultUsage {Usage: []int{0, 0, 0}}
				usage.Usage[thread] += 1
				overlaps[arg.Res] = usage
			}
		}
	default:
	}
}

func callUsesAnyResultArg(c Call) bool {
	for _, arg := range c.Args {
		if argUsesResultArg(arg) {
			return true
		}
	}

	return false
}

func (p *Prog) ShouldExecuteProg() bool {
	if !p.HasAllThreads() {
		return false
	}

	overlaps := make(map[Arg]resultUsage)

	for _, call := range p.Calls {
		ti := call.Props.ThreadIndex

		//log.Logf(1, "AAAA ti=%d call=%#v\n", ti, call)

		if ti == 0 {
			if call.Ret == nil && !callUsesAnyResultArg(call) {
				/* All syscalls on the parent thread must allocate a resource or use a resource*/
				return false
			}
		} else {
			foundReturnArg := false
			for _, arg := range call.Args {
				if argUsesResultArg(arg) {
					foundReturnArg = true
				}

				findOverlap(overlaps, ti, arg)
			}

			if !foundReturnArg {
				return false
			}

/*
			if !threadNUsesResultArg(call.Ret, 1) {
				return false
			}

			if !threadNUsesResultArg(call.Ret, 2) {
				return false
			}
*/
		}
	}

	//log.Logf(1, "AAAA overlaps=%#v\n", overlaps)

	for _, usage := range overlaps {
		//log.Logf(1, "AAAA arg=%#v\n", arg)
		//log.Logf(1, "AAAA usage=%#v\n", usage)
		if usage.Usage[1] > 0 && usage.Usage[2] > 0 {
			return true
		}
	}

	return false
}

func (p *Prog) sanitizeFix() {
	if err := p.sanitize(true); err != nil {
		panic(err)
	}
}

func (p *Prog) sanitize(fix bool) error {
	for _, c := range p.Calls {
		if err := p.Target.sanitize(c, fix); err != nil {
			return err
		}
	}
	return nil
}

// TODO: This method might be more generic - it can be applied to any struct.
func (props *CallProps) ForeachProp(f func(fieldName, key string, value reflect.Value)) {
	valueObj := reflect.ValueOf(props).Elem()
	typeObj := valueObj.Type()
	for i := 0; i < valueObj.NumField(); i++ {
		fieldValue := valueObj.Field(i)
		fieldType := typeObj.Field(i)
		f(fieldType.Name, fieldType.Tag.Get("key"), fieldValue)
	}
}
