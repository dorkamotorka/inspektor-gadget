package uprobetracer 

import (
	"bytes"
	"debug/buildinfo"
	"debug/elf"
	"debug/gosym"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"golang.org/x/arch/x86/x86asm"
)

const (
	GoTlsReadFunc         = "crypto/tls.(*Conn).Read"
	GoTlsWriteFunc        = "crypto/tls.(*Conn).writeRecordLocked"
)

var (
	ErrorGoBinNotFound            = errors.New("the executable program (compiled by Golang) was not found")
	ErrorSymbolEmpty              = errors.New("symbol is empty")
	ErrorSymbolNotFound           = errors.New("symbol not found")
	ErrorSymbolNotFoundFromTable  = errors.New("symbol not found from table")
	ErrorNoRetFound               = errors.New("no RET instructions found")
	ErrorNoFuncFoundFromSymTabFun = errors.New("no function found from golang symbol table with Func Name")
	ErrorTextSectionNotFound      = errors.New("`.text` section not found")
)

// From go/src/debug/gosym/pclntab.go
const (
	go12magic  = 0xfffffffb
	go116magic = 0xfffffffa
	go118magic = 0xfffffff0
	go120magic = 0xfffffff1
)

// Select the magic number based on the Go version
func magicNumber(goVersion string) []byte {
	bs := make([]byte, 4)
	var magic uint32
	if strings.Compare(goVersion, "go1.20") >= 0 {
		magic = go120magic
	} else if strings.Compare(goVersion, "go1.18") >= 0 {
		magic = go118magic
	} else if strings.Compare(goVersion, "go1.16") >= 0 {
		magic = go116magic
	} else {
		magic = go12magic
	}
	binary.LittleEndian.PutUint32(bs, magic)
	return bs
}

// Returns write and read function offsets
func GetFunctionOffsets(binaryPath string) (uint64, []uint64) {
	var writeAddr uint64
	var readAddrs []uint64

	var err error
	var bi *buildinfo.BuildInfo
	// Read the build information of the Go application
	bi, err = buildinfo.ReadFile(binaryPath)
	if err != nil {
		return 0, nil
	}

	var goElf *elf.File
	goElf, err = elf.Open(binaryPath)
	if err != nil {
		return 0, nil
	}

	var goElfArch, machineStr string
	machineStr = goElf.FileHeader.Machine.String()
	switch machineStr {
	case elf.EM_AARCH64.String():
		goElfArch = "arm64"
	case elf.EM_X86_64.String():
		goElfArch = "amd64"
	default:
		goElfArch = "unsupported_arch"
	}

	if goElfArch != runtime.GOARCH {
		fmt.Errorf("go Application not match, want:%s, have:%s", runtime.GOARCH, goElfArch)
		return 0, nil
	}
	switch goElfArch {
	case "amd64":
	case "arm64":
	default:
		fmt.Errorf("unsupport CPU arch :%s", goElfArch)
		return 0, nil
	}

	isPieBuildMode := false
	// If built with PIE and stripped, gopclntab is
	// unlabeled and nested under .data.rel.ro.
	for _, bs := range bi.Settings {
		if bs.Key == "-buildmode" {
			if bs.Value == "pie" {
				isPieBuildMode = true
			}
			break
		}
	}


	var goSymTab *gosym.Table
	if isPieBuildMode {
		goSymTab, err = readTable(goElf, bi)
		if err != nil {
			return 0, nil
		}
		writeAddr, err = findPieSymbolAddr(GoTlsWriteFunc, goSymTab)
		if err != nil {
			fmt.Errorf("%s symbol address error:%s", GoTlsWriteFunc, err.Error())
			return 0, nil
		}

		readAddrs, err = findRetOffsetsPie(GoTlsReadFunc, goElf, goSymTab)
		if err != nil {
			return 0, nil
		}
	} else {
		readAddrs, err = findRetOffsets(GoTlsReadFunc, goElf)
		if err == nil {
			return 0, nil
		}

		goSymTab, err = readTable(goElf, bi)
		if err != nil {
			return 0, nil
		}
		writeAddr, err = findSymbolAddr(GoTlsWriteFunc, goSymTab, goElf)
		if err != nil {
			fmt.Errorf("%s find symbol addr error:%w", GoTlsWriteFunc, err)
			return 0, nil
		}

		readAddrs, err = findSymbolRetOffsets(GoTlsReadFunc, goSymTab, goElf)
		if err != nil {
			return 0, nil
		}
	}
	return writeAddr, readAddrs

}

// decodeInstruction Decode into assembly instructions and identify the RET instruction to return the offset.
func decodeInstruction(instHex []byte) ([]uint64, error) {
	var offsets []uint64
	for i := 0; i < len(instHex); {
		inst, err := x86asm.Decode(instHex[i:], 64)
		if err != nil {
			return nil, err
		}
		if inst.Op == x86asm.RET {
			offsets = append(offsets, uint64(i))
		}
		i += inst.Len
	}
	return offsets, nil
}

// FindRetOffsets searches for the addresses of all RET instructions within
// the instruction set associated with the specified symbol in an ELF program.
// It is used for mounting uretprobe programs for Golang programs,
// which are actually mounted via uprobe on these addresses.
func findRetOffsets(symbolName string, goElf *elf.File) ([]uint64, error) {
	var err error
	var allSymbs []elf.Symbol

	goSymbs, _ := goElf.Symbols()
	if len(goSymbs) > 0 {
		allSymbs = append(allSymbs, goSymbs...)
	}
	goDynamicSymbs, _ := goElf.DynamicSymbols()
	if len(goDynamicSymbs) > 0 {
		allSymbs = append(allSymbs, goDynamicSymbs...)
	}

	if len(allSymbs) == 0 {
		return nil, ErrorSymbolEmpty
	}

	var found bool
	var symbol elf.Symbol
	for _, s := range allSymbs {
		if s.Name == symbolName {
			symbol = s
			found = true
			break
		}
	}

	if !found {
		return nil, fmt.Errorf("Error: Symbol not found")
	}

	section := goElf.Sections[symbol.Section]

	var elfText []byte
	elfText, err = section.Data()
	if err != nil {
		return nil, err
	}

	start := symbol.Value - section.Addr
	end := start + symbol.Size

	var offsets []uint64
	var instHex = elfText[start:end]
	offsets, _ = decodeInstruction(instHex)
	if len(offsets) == 0 {
		return offsets, fmt.Errorf("Error: no ret found")
	}

	address := symbol.Value
	for _, prog := range goElf.Progs {
		// Skip uninteresting segments.
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= symbol.Value && symbol.Value < (prog.Vaddr+prog.Memsz) {
			// stackoverflow.com/a/40249502
			address = symbol.Value - prog.Vaddr + prog.Off
			break
		}
	}
	for i, offset := range offsets {
		offsets[i] = uint64(address) + offset
	}
	return offsets, nil
}

func readTable(goElf *elf.File, bi *buildinfo.BuildInfo) (*gosym.Table, error) {
	sectionLabel := ".gopclntab"
	section := goElf.Section(sectionLabel)
	if section == nil {
		// binary may be built with -pie
		sectionLabel = ".data.rel.ro.gopclntab"
		section = goElf.Section(sectionLabel)
		if section == nil {
			sectionLabel = ".data.rel.ro"
			section = goElf.Section(sectionLabel)
			if section == nil {
				return nil, fmt.Errorf("could not read section %s", sectionLabel)
			}
		}
	}
	tableData, err := section.Data()
	if err != nil {
		return nil, fmt.Errorf("found section but could not read %s", sectionLabel)
	}
	// Find .gopclntab by magic number even if there is no section label
	magic := magicNumber(bi.GoVersion)
	pclntabIndex := bytes.Index(tableData, magic)
	if pclntabIndex < 0 {
		return nil, fmt.Errorf("could not find magic number")
	}
	tableData = tableData[pclntabIndex:]
	var addr uint64
	{
		// get textStart from pclntable
		// please see https://go-review.googlesource.com/c/go/+/366695
		// tableData
		ptrSize := uint32(tableData[7])
		if ptrSize == 4 {
			addr = uint64(binary.LittleEndian.Uint32(tableData[8+2*ptrSize:]))
		} else {
			addr = binary.LittleEndian.Uint64(tableData[8+2*ptrSize:])
		}
	}
	lineTable := gosym.NewLineTable(tableData, addr)
	symTable, err := gosym.NewTable([]byte{}, lineTable)
	if err != nil {
		return nil, fmt.Errorf("Error: Symbol not found from table")
	}
	return symTable, nil
}

func findRetOffsetsPie(lfunc string, goElf *elf.File, goSymTab *gosym.Table) ([]uint64, error) {
	var offsets []uint64
	var address uint64
	var err error
	address, err = findPieSymbolAddr(lfunc, goSymTab)
	if err != nil {
		return offsets, err
	}
	f := goSymTab.LookupFunc(lfunc)
	funcLen := f.End - f.Entry
	for _, prog := range goElf.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		// via https://github.com/golang/go/blob/a65a2bbd8e58cd77dbff8a751dbd6079424beb05/src/cmd/internal/objfile/elf.go#L174
		data := make([]byte, funcLen)
		_, err = prog.ReadAt(data, int64(address-prog.Vaddr))
		if err != nil {
			return offsets, fmt.Errorf("finding function return: %w", err)
		}
		offsets, err = decodeInstruction(data)
		if err != nil {
			return offsets, fmt.Errorf("finding function return: %w", err)
		}
		for i, offset := range offsets {
			offsets[i] = uint64(address) + offset
		}
		return offsets, nil
	}
	return offsets, errors.New("cant found gotls symbol offsets")
}

func findPieSymbolAddr(lfunc string, goSymTab *gosym.Table) (uint64, error) {
	f := goSymTab.LookupFunc(lfunc)
	if f == nil {
		return 0, fmt.Errorf("Error: No func found from sym tab fun")
	}
	return f.Value, nil
}

func findSymbolAddr(lfunc string, goSymTab *gosym.Table, goElf *elf.File) (uint64, error) {
	f := goSymTab.LookupFunc(lfunc)
	if f == nil {
		return 0, ErrorNoFuncFoundFromSymTabFun
	}

	textSect := goElf.Section(".text")
	if textSect == nil {
		return 0, ErrorTextSectionNotFound
	}
	return f.Entry - textSect.Addr + textSect.Offset, nil
}

func findSymbolRetOffsets(lfunc string, goSymTab *gosym.Table, goElf *elf.File) ([]uint64, error) {
	f := goSymTab.LookupFunc(lfunc)
	if f == nil {
		return nil, fmt.Errorf("Error: No func found from sym tab fun")
	}

	textSect := goElf.Section(".text")
	if textSect == nil {
		return nil, fmt.Errorf("Error: Text section not found")
	}
	textData, err := textSect.Data()
	if err != nil {
		return nil, err
	}

	var (
		start = f.Entry - textSect.Addr
		end   = f.End - textSect.Addr
	)

	if end <= start || start > textSect.Size || end > textSect.Size {
		return nil, fmt.Errorf("invalid function range start: %d, end: %d", start, end)
	}

	offsets, err := decodeInstruction(textData[start:end])
	if err != nil {
		return nil, err
	}
	for _, prog := range goElf.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}

		if prog.Vaddr <= f.Entry && f.Entry < (prog.Vaddr+prog.Memsz) {
			// stackoverflow.com/a/40249502
			address := f.Entry - prog.Vaddr + prog.Off
			for i, offset := range offsets {
				offsets[i] = uint64(address) + offset
			}
			return offsets, nil
		}
	}
	return nil, errors.New("cant found gotls ret offsets")
}