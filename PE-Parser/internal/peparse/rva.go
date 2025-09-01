package peparse

import (
	"debug/pe"
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
)

func hexDumpWithOffsets(sectionRawOffset uint32, data []byte) string {
	var b strings.Builder
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		fmt.Fprintf(&b, "%08X  ", sectionRawOffset+uint32(i))
		for j := 0; j < 16; j++ {
			if i+j < len(data) {
				fmt.Fprintf(&b, "%02X ", data[i+j])
			} else {
				b.WriteString("   ")
			}
		}
		b.WriteString(" ")
		for _, by := range chunk {
			if by >= 32 && by <= 126 {
				b.WriteByte(by)
			} else {
				b.WriteByte('.')
			}
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func extractStrings(data []byte, minLen int) []string {
	if minLen < 1 {
		minLen = 1
	}
	var out []string
	var buf strings.Builder
	flush := func() {
		if buf.Len() >= minLen {
			out = append(out, buf.String())
		}
		buf.Reset()
	}
	for _, b := range data {
		r := rune(b)
		if unicode.IsPrint(r) && r != '\t' && r != '\r' && r != '\n' {
			buf.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

func getOptional(f *pe.File) (is64 bool, oh32 *pe.OptionalHeader32, oh64 *pe.OptionalHeader64) {
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader32:
		return false, oh, nil
	case *pe.OptionalHeader64:
		return true, nil, oh
	default:
		return false, nil, nil
	}
}

func rvaToOff(f *pe.File, rva uint32) (uint32, bool) {
	for _, s := range f.Sections {
		va := s.VirtualAddress
		vsz := s.VirtualSize
		if rva >= va && rva < va+vsz {
			return s.Offset + (rva - va), true
		}
	}
	return 0, false
}

func readU16(b []byte, off uint32) (uint16, bool) {
	if int(off)+2 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint16(b[off:]), true
}
func readU32(b []byte, off uint32) (uint32, bool) {
	if int(off)+4 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint32(b[off:]), true
}
func readU64(b []byte, off uint32) (uint64, bool) {
	if int(off)+8 > len(b) {
		return 0, false
	}
	return binary.LittleEndian.Uint64(b[off:]), true
}

func readCStringRVA(f *pe.File, bin []byte, rva uint32) (string, bool) {
	off, ok := rvaToOff(f, rva)
	if !ok || int(off) >= len(bin) {
		return "", false
	}
	i := off
	for i < uint32(len(bin)) && bin[i] != 0 {
		i++
	}
	return string(bin[off:i]), true
}

type importDesc struct {
	OriginalFirstThunk uint32
	TimeDateStamp      uint32
	ForwarderChain     uint32
	NameRVA            uint32
	FirstThunk         uint32
}

func parseImports(f *pe.File, bin []byte, is64 bool) ImportReport {
	var r ImportReport
	_, oh32, oh64 := getOptional(f)
	var dir pe.DataDirectory
	if oh32 != nil {
		dir = oh32.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	} else if oh64 != nil {
		dir = oh64.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	} else {
		r.Note = "no optional header"
		return r
	}
	if dir.VirtualAddress == 0 || dir.Size < 20 {
		return r
	}
	baseOff, ok := rvaToOff(f, dir.VirtualAddress)
	if !ok {
		r.Note = "bad import directory RVA"
		return r
	}

	for off := baseOff; ; off += 20 {
		if int(off)+20 > len(bin) {
			break
		}
		id := importDesc{
			OriginalFirstThunk: binary.LittleEndian.Uint32(bin[off+0:]),
			TimeDateStamp:      binary.LittleEndian.Uint32(bin[off+4:]),
			ForwarderChain:     binary.LittleEndian.Uint32(bin[off+8:]),
			NameRVA:            binary.LittleEndian.Uint32(bin[off+12:]),
			FirstThunk:         binary.LittleEndian.Uint32(bin[off+16:]),
		}
		if id.OriginalFirstThunk == 0 && id.NameRVA == 0 && id.FirstThunk == 0 {
			break
		}
		dll, ok := readCStringRVA(f, bin, id.NameRVA)
		if !ok || dll == "" {
			dll = "<unknown>"
		}
		funcs := parseImportNames(f, bin, id, is64)
		r.DLLs = append(r.DLLs, ImportDLL{Name: strings.ToLower(dll), Functions: funcs})
	}
	return r
}

func parseImportNames(f *pe.File, bin []byte, id importDesc, is64 bool) []string {
	thunk := id.OriginalFirstThunk
	if thunk == 0 {
		thunk = id.FirstThunk
	}
	off, ok := rvaToOff(f, thunk)
	if !ok {
		return nil
	}
	var names []string
	for {
		if !is64 {
			val, ok := readU32(bin, off)
			if !ok || val == 0 {
				break
			}
			off += 4
			if val&0x80000000 != 0 {
				names = append(names, fmt.Sprintf("#%d", val&0xFFFF))
				continue
			}
			rva := uint32(val)
			name, ok := readCStringRVA(f, bin, rva+2)
			if !ok {
				name = "<name>"
			}
			names = append(names, name)
		} else {
			val, ok := readU64(bin, off)
			if !ok || val == 0 {
				break
			}
			off += 8
			if val&0x8000000000000000 != 0 {
				names = append(names, fmt.Sprintf("#%d", uint32(val&0xFFFF)))
				continue
			}
			rva := uint32(val)
			name, ok := readCStringRVA(f, bin, rva+2)
			if !ok {
				name = "<name>"
			}
			names = append(names, name)
		}
	}
	return names
}

type exportDir struct {
	Characteristics      uint32
	TimeDateStamp        uint32
	MajorVersion         uint16
	MinorVersion         uint16
	NameRVA              uint32
	Base                 uint32
	NumberOfFunctions    uint32
	NumberOfNames        uint32
	AddressOfFunctions   uint32
	AddressOfNames       uint32
	AddressOfNameOrdinal uint32
}

func parseExports(f *pe.File, bin []byte) ExportReport {
	var r ExportReport
	_, oh32, oh64 := getOptional(f)
	var dir pe.DataDirectory
	if oh32 != nil {
		dir = oh32.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	} else if oh64 != nil {
		dir = oh64.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT]
	} else {
		r.Note = "no optional header"
		return r
	}
	if dir.VirtualAddress == 0 || dir.Size < 40 {
		return r
	}
	baseOff, ok := rvaToOff(f, dir.VirtualAddress)
	if !ok || int(baseOff)+40 > len(bin) {
		r.Note = "bad export directory RVA"
		return r
	}
	ed := exportDir{
		Characteristics:      binary.LittleEndian.Uint32(bin[baseOff+0:]),
		TimeDateStamp:        binary.LittleEndian.Uint32(bin[baseOff+4:]),
		MajorVersion:         binary.LittleEndian.Uint16(bin[baseOff+8:]),
		MinorVersion:         binary.LittleEndian.Uint16(bin[baseOff+10:]),
		NameRVA:              binary.LittleEndian.Uint32(bin[baseOff+12:]),
		Base:                 binary.LittleEndian.Uint32(bin[baseOff+16:]),
		NumberOfFunctions:    binary.LittleEndian.Uint32(bin[baseOff+20:]),
		NumberOfNames:        binary.LittleEndian.Uint32(bin[baseOff+24:]),
		AddressOfFunctions:   binary.LittleEndian.Uint32(bin[baseOff+28:]),
		AddressOfNames:       binary.LittleEndian.Uint32(bin[baseOff+32:]),
		AddressOfNameOrdinal: binary.LittleEndian.Uint32(bin[baseOff+36:]),
	}
	if name, ok := readCStringRVA(f, bin, ed.NameRVA); ok {
		r.DLLName = name
	}

	funcsOff, ok1 := rvaToOff(f, ed.AddressOfFunctions)
	namesOff, ok2 := rvaToOff(f, ed.AddressOfNames)
	ordsOff, ok3 := rvaToOff(f, ed.AddressOfNameOrdinal)
	if !ok1 || !ok2 || !ok3 {
		r.Note = "malformed export arrays"
		return r
	}

	nNames := int(ed.NumberOfNames)
	nFuncs := int(ed.NumberOfFunctions)
	if nNames < 0 || nFuncs < 0 || nNames > 1<<20 || nFuncs > 1<<20 {
		r.Note = "suspicious export counts"
		return r
	}

	for i := 0; i < nNames; i++ {
		if int(namesOff)+4 > len(bin) || int(ordsOff)+2 > len(bin) {
			break
		}
		nameRVA := binary.LittleEndian.Uint32(bin[namesOff:])
		ordIdx := binary.LittleEndian.Uint16(bin[ordsOff:])
		namesOff += 4
		ordsOff += 2

		name, _ := readCStringRVA(f, bin, nameRVA)
		idx := int(ordIdx)
		if idx < 0 || idx >= nFuncs {
			continue
		}
		funcRVA := binary.LittleEndian.Uint32(bin[funcsOff+uint32(idx*4):])
		r.Symbols = append(r.Symbols, ExportSymbol{
			Name:    name,
			Ordinal: uint16(ed.Base) + uint16(idx),
			RVA:     funcRVA,
		})
	}
	return r
}

type resDir struct {
	Characteristics uint32
	TimeDateStamp   uint32
	MajorVersion    uint16
	MinorVersion    uint16
	NNamed          uint16
	NId             uint16
}
type resEntry struct {
	NameOrID     uint32
	OffsetToData uint32
}

func parseResources(f *pe.File, bin []byte) ResourceReport {
	var r ResourceReport
	_, oh32, oh64 := getOptional(f)
	var dir pe.DataDirectory
	if oh32 != nil {
		dir = oh32.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
	} else if oh64 != nil {
		dir = oh64.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_RESOURCE]
	} else {
		r.Note = "no optional header"
		return r
	}
	if dir.VirtualAddress == 0 || dir.Size < 16 {
		return r
	}
	baseOff, ok := rvaToOff(f, dir.VirtualAddress)
	if !ok || int(baseOff)+16 > len(bin) {
		r.Note = "bad resource directory RVA"
		return r
	}
	root := resDir{
		Characteristics: le32(bin, baseOff+0),
		TimeDateStamp:   le32(bin, baseOff+4),
		MajorVersion:    le16(bin, baseOff+8),
		MinorVersion:    le16(bin, baseOff+10),
		NNamed:          le16(bin, baseOff+12),
		NId:             le16(bin, baseOff+14),
	}
	total := int(root.NNamed) + int(root.NId)
	entryOff := baseOff + 16
	types := make(map[uint32]int)
	for i := 0; i < total; i++ {
		if int(entryOff)+8 > len(bin) {
			break
		}
		e := resEntry{
			NameOrID:     le32(bin, entryOff+0),
			OffsetToData: le32(bin, entryOff+4),
		}
		entryOff += 8

		isID := (e.NameOrID & 0x80000000) == 0
		var typeID uint32
		if isID {
			typeID = e.NameOrID
		} else {
			typeID = 0
		}
		if (e.OffsetToData & 0x80000000) != 0 {
			subRVA := dir.VirtualAddress + (e.OffsetToData &^ 0x80000000)
			subOff, ok := rvaToOff(f, subRVA)
			if ok && int(subOff)+16 <= len(bin) {
				rd := resDir{
					NNamed: le16(bin, subOff+12),
					NId:    le16(bin, subOff+14),
				}
				types[typeID] += int(rd.NNamed) + int(rd.NId)
			}
		}
	}
	for id, cnt := range types {
		r.Types = append(r.Types, ResourceTypeSummary{
			TypeID:   id,
			TypeName: resourceTypeName(id),
			Count:    cnt,
		})
	}
	return r
}

func resourceTypeName(id uint32) string {
	switch id {
	case 1:
		return "RT_CURSOR (1)"
	case 2:
		return "RT_BITMAP (2)"
	case 3:
		return "RT_ICON (3)"
	case 4:
		return "RT_MENU (4)"
	case 5:
		return "RT_DIALOG (5)"
	case 6:
		return "RT_STRING (6)"
	case 7:
		return "RT_FONTDIR (7)"
	case 8:
		return "RT_FONT (8)"
	case 9:
		return "RT_ACCELERATOR (9)"
	case 10:
		return "RT_RCDATA (10)"
	case 11:
		return "RT_MESSAGETABLE (11)"
	case 12:
		return "RT_GROUP_CURSOR (12)"
	case 14:
		return "RT_GROUP_ICON (14)"
	case 16:
		return "RT_VERSION (16)"
	case 24:
		return "RT_MANIFEST (24)"
	case 0:
		return "RT_(named) (?)"
	default:
		return fmt.Sprintf("RT_%d", id)
	}
}

func le32(b []byte, off uint32) uint32 {
	if int(off)+4 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint32(b[off:])
}
func le16(b []byte, off uint32) uint16 {
	if int(off)+2 > len(b) {
		return 0
	}
	return binary.LittleEndian.Uint16(b[off:])
}
