#### PE-Viewer on Steroids
A Golang binary to parse and display detailed information about Portable Executable (PE) files, including headers, sections, imports, exports, resources, and more.
#### Features
- Comprehensive PE file parsing
- Detailed output of PE headers, sections, imports, exports, resources, and more
- Command-line interface for easy usage
- Written in Go for performance and portability
- HTML report generation for better visualization
- Support for StringSifter integration
#### Installation
- ```go build -o PE-Parser.exe ./cmd/peview```
- Usage: ```PE-Parser.exe -file ./test.exe -strings -minstrlen 10 -html -rank```