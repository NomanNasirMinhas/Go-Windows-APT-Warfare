package main

import (
	"bytes"
	"debug/pe"
	"flag"
	"fmt"
	"log"
	"os"
	"unicode"
)

func main() {
	pePath := flag.String("file", "", "Path to the PE file")
	flag.Parse()

	if *pePath == "" {
		fmt.Fprintln(os.Stderr, "Usage: go run main.go -file <path-to-pe-file>")
		os.Exit(1)
	}

	peFile, err := pe.Open(*pePath)
	if err != nil {
		log.Fatalf("Failed to open PE file: %v", err)
	}
	defer peFile.Close()

	fmt.Printf("Found %d sections:\n", len(peFile.Sections))
	for _, sec := range peFile.Sections {
		fmt.Printf("- Name: %s, VirtualSize: 0x%X, Size: 0x%X\n", sec.Name, sec.VirtualSize, sec.Size)
	}
	fmt.Println()

	for _, sec := range peFile.Sections {
		fmt.Printf("=== Section: %s ===\n", sec.Name)

		data, err := sec.Data()
		if err != nil {
			fmt.Printf("Error reading section data: %v\n", err)
			continue
		}

		fmt.Println("Hex dump:")
		for i := 0; i < len(data); i += 16 {
			end := i + 16
			if end > len(data) {
				end = len(data)
			}
			chunk := data[i:end]
			fmt.Printf("%08X  ", sec.Offset+uint32(i)) //print as uppercase hexadecimal with exactly 8 digits, padding with leading zeros if necessary
			for _, b := range chunk {
				fmt.Printf("%02X ", b) // print each byte as uppercase hexadecimal with exactly 2 digits, padding with leading zeros if necessary
			}
			fmt.Println()
		}
		fmt.Println()

		fmt.Println("Strings (printable sequences >= 4 chars):")
		// printStrings(data, 4) // Uncommenting to print strings of at least 4 printable characters
		fmt.Println()
	}
}

func printStrings(data []byte, minLen int) {
	var buf bytes.Buffer
	for _, b := range data {
		r := rune(b)
		if unicode.IsPrint(r) {
			buf.WriteRune(r)
		} else {
			if buf.Len() >= minLen {
				fmt.Println(buf.String())
			}
			buf.Reset()
		}
	}
	if buf.Len() >= minLen {
		fmt.Println(buf.String())
	}
}
