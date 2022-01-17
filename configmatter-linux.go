// ┌──────────────────────────────────┐
// │ Marius 'f0wL' Genheimer, 2021    │
// └──────────────────────────────────┘

package main

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"text/tabwriter"

	"github.com/fatih/color"
)

// check errors as they occur and panic :o
func check(e error) {
	if e != nil {
		panic(e)
	}
}

// ioReader acts as a wrapper function to make opening the file even easier
func ioReader(file string) io.ReaderAt {
	r, err := os.Open(file)
	check(err)
	return r
}

// calcSHA256 reads the sample file and calculates its SHA-256 hashsum
func calcSHA256(file string) string {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := sha256.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// calcMD5 reads the sample file and calculates its SHA-256 hashsum
func calcMD5(file string) string {

	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	h := md5.New()
	_, hashErr := io.Copy(h, f)
	check(hashErr)
	return hex.EncodeToString(h.Sum(nil))
}

// getFileInfo returns the size on disk of the specified file
func getFileInfo(file string) int64 {
	f, readErr := os.Open(file)
	check(readErr)
	defer f.Close()

	fileInfo, fileErr := f.Stat()
	check(fileErr)

	return fileInfo.Size()
}

// base64Decode decodes base64 data passed as a byte array; returns a byte array
func base64Decode(message []byte) (b []byte) {
	b = make([]byte, base64.StdEncoding.DecodedLen(len(message)))
	l, base64Err := base64.StdEncoding.Decode(b, message)
	check(base64Err)
	return b[:l]
}

// zlibDecompress decompresses raw zlib data passed as a byte array; returns a byte array
func zlibDecompress(data []byte) []byte {
	reader := bytes.NewReader(data)
	zr, zlibErr := zlib.NewReader(reader)
	check(zlibErr)
	defer zr.Close()

	contents, readErr := ioutil.ReadAll(zr)
	check(readErr)
	return contents
}

// Flag variables for commandline arguments
var debugFlag bool
var verboseFlag bool
var jsonFlag bool

func main() {

	fmt.Printf("\n             *       +")
	fmt.Printf("\n       '                  |          ___           __ _      __  __      _   _         ")
	fmt.Printf("\n   ()    .-.,=''''=.    - o -       / __|___ _ _  / _(_)__ _|  \\/  |__ _| |_| |_ ___ _ _ ")
	fmt.Printf("\n         '=/_       \\     |        | (__/ _ \\ ' \\|  _| / _` | |\\/| / _` |  _|  _/ -_) '_|")
	fmt.Printf("\n      *   |  '=._    |              \\___\\___/_||_|_| |_\\__, |_|  |_\\__,_|\\__|\\__\\___|_| ")
	fmt.Printf("\n           \\     `=./`,        '                       |___/                               ")
	fmt.Printf("\n        .   '=.__.=' `='      *")
	fmt.Printf("\n  +                       +         BlackMatter Linux Ransomware Configuration Extractor")
	fmt.Printf("\n    O      *        '       .       Marius 'f0wL' Genheimer | https://dissectingmalwa.re\n\n")

	// parse passed flags
	flag.BoolVar(&jsonFlag, "j", false, "Write extracted config to a JSON file")
	flag.BoolVar(&verboseFlag, "v", false, "Verbose output")
	flag.BoolVar(&debugFlag, "d", false, "More verbose output than -v. Useful for debugging this config extractor.")
	flag.Parse()

	// check passed arguments
	if flag.NArg() == 0 {
		color.Red("✗ No path to sample provided.\n\n")
		os.Exit(1)
	}

	// calculate hash sums of the sample
	md5sum := calcMD5(flag.Args()[0])
	sha256sum := calcSHA256(flag.Args()[0])

	// print useful sample metadata
	w1 := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', 0)
	fmt.Fprintln(w1, "→ File size (bytes): \t", getFileInfo(flag.Args()[0]))
	fmt.Fprintln(w1, "→ Sample MD5: \t", md5sum)
	fmt.Fprintln(w1, "→ Sample SHA-256: \t", sha256sum)
	w1.Flush()

	// open the sample in an ioReader
	sample := ioReader(flag.Args()[0])

	// parse the ELF
	f, parseErr := elf.NewFile(sample)
	check(parseErr)

	// dump out the contents of the .app.version section
	versionSection, dumpErr := f.Section(".app.version").Data()
	check(dumpErr)
	mwVersion := string(bytes.Trim(versionSection, "\x00"))

	// dump out the contents of the .cfgETD section
	isDecryptor := false

	var configData []byte
	if f.Section(".cfgETD") != nil {
		configData, dumpErr = f.Section(".cfgETD").Data()
		check(dumpErr)
	} else if f.Section(".cfgDTD") != nil {
		color.Yellow("Couldn't find section .cfgETD, trying to dump .cfgDTD instead (Decryptor).")
		configData, dumpErr = f.Section(".cfgDTD").Data()
		check(dumpErr)
		isDecryptor = true
	} else {
		color.Red("Couldn't find section .cfgETD or .cfgDTD.")
	}

	cleanRaw := bytes.Trim(configData, "\x00")

	// decode the base64 encoded data
	decodedCompressed := base64Decode(cleanRaw)

	if debugFlag {
		fmt.Printf("\nBase-64 decoded:\n")
		fmt.Print(hex.Dump(decodedCompressed))
	}

	// decompress the zlib compressed data
	decompressed := zlibDecompress(decodedCompressed)

	if debugFlag {
		fmt.Printf("\nDecompressed config blob:\n")
		fmt.Print(hex.Dump(decompressed))
	}

	index := 0
	key_pos := 0
	key := decompressed[:32]
	ciphertext := decompressed[32:]
	length := len(ciphertext)
	plaintext := make([]byte, length)

	if debugFlag {
		fmt.Printf("\nXOR Key: \n%v\n", hex.Dump(key))
		fmt.Printf("Ciphertext Length: %v / %x\n", length, length)
	}

	// ┌───────────────────────────────────────────────────────────┐
	// │ Decrypting the configuration                              │
	// | The first 32 bytes of the config blob contain the XOR Key |
	// └───────────────────────────────────────────────────────────┘

	for index < length {
		kbyte := key[key_pos]
		if ciphertext[index] != kbyte {
			plaintext[index] = ciphertext[index] ^ kbyte
			key_pos = key_pos + 1
			if key_pos == 32 {
				key_pos = 0
			}
		} else {
			plaintext[index] = ciphertext[index]
		}
		index = index + 1
	}

	if jsonFlag {
		// write json config to a file
		filename := "config-" + md5sum + ".json"
		writeErr := ioutil.WriteFile(filename, plaintext, 0644)
		check(writeErr)
		color.Green("\n✓ Wrote decrypted configuration to %v\n", filename)
	}

	if verboseFlag {
		// hexdump the whole config file
		fmt.Printf("\nDecrypted config blob:\n%v", hex.Dump(plaintext))
	}

	// initialize a variable to store the config in; the structures are defined in blackmatter-linux_structs.go
	var configEnc BlackmatterConfigEnc
	var configDec BlackmatterConfigDec

	if !isDecryptor {
		// unmarshal the decrypted config into the struct
		jsonErr := json.Unmarshal(plaintext, &configEnc)
		check(jsonErr)

		// print extracted configuration features
		color.Green("\n✓ Extracted Configuration:\n")

		fmt.Fprintln(w1, "\n→ Ransomware Version: \t", mwVersion)
		fmt.Fprintln(w1, "→ RSA Public Key: \t", configEnc.RSAKey[0:64]+"...")
		fmt.Fprintln(w1, "→ Self-Remove: \t", configEnc.SelfDelete)
		fmt.Fprintln(w1, "→ Worker Concurrency: \t", configEnc.Concurrency)
		fmt.Fprintln(w1, "→ Log Level: \t", configEnc.Log.Level)
		fmt.Fprintln(w1, "→ Log Path: \t", configEnc.Log.Path)
		fmt.Fprintln(w1, "→ Ransomnote Filename: \t", configEnc.Message.Name)
		fmt.Fprintln(w1, "→ Bot ID: \t", configEnc.Landing.ID)
		fmt.Fprintln(w1, "→ AES Key: \t", configEnc.Landing.Key)
		fmt.Fprintln(w1, "→ C&C URLs: \t", configEnc.Landing.URLs)
		fmt.Fprintln(w1, "→ Ignore VMs: \t", configEnc.KillVM.Ignore)
		fmt.Fprintln(w1, "→ Ignore Processes: \t", configEnc.KillProcess.List)
		w1.Flush()

		// print the ransomnote
		color.Green("\n✓ Ransomnote:\n")
		fmt.Printf("%v\n", configEnc.Message.Content)
	} else {
		// unmarshal the decrypted config into the struct
		jsonErr := json.Unmarshal(plaintext, &configDec)
		check(jsonErr)

		// print extracted configuration features
		color.Green("\n✓ Extracted Configuration:\n")

		fmt.Fprintln(w1, "\n→ Ransomware Version: \t", mwVersion)
		fmt.Fprintln(w1, "→ RSA Public Key: \t", configDec.RSAKey[0:64]+"...")
		fmt.Fprintln(w1, "→ Self-Remove: \t", configDec.SelfDelete)
		fmt.Fprintln(w1, "→ Worker Concurrency: \t", configDec.Concurrency)
		fmt.Fprintln(w1, "→ Log Level: \t", configDec.Log.Level)
		fmt.Fprintln(w1, "→ Log Path: \t", configDec.Log.Path)
		fmt.Fprintln(w1, "→ Ransomnote Filename: \t", configDec.Message.Name)
		w1.Flush()
	}
}
