// Copyright 2021 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

type eof1Test struct {
	code     string
	codeSize uint16
	dataSize uint16
}

var eof1ValidTests = []eof1Test{
	{"EF00010100010000", 1, 0},
	{"EF0001010002006000", 2, 0},
	{"EF0001010002020001006000AA", 2, 1},
	{"EF0001010002020004006000AABBCCDD", 2, 4},
	{"EF00010100040200020060006001AABB", 4, 2},
	{"EF000101000602000400600060016002AABBCCDD", 6, 4},
	{"EF000101000100FE", 1, 0}, // INVALID is defined
	{"EF0001010021007F0000000000000000000000000000000000000000000000000000000000000000", 33, 0},       // PUSH32
	{"EF0001010021007F0C0D0E0F1E1F2122232425262728292A2B2C2D2E2F494A4B4C4D4E4F5C5D5E5F", 33, 0},       // undefined instructions inside push data
	{"EF000101000102002000000C0D0E0F1E1F2122232425262728292A2B2C2D2E2F494A4B4C4D4E4F5C5D5E5F", 1, 32}, // undefined instructions inside data section
}

type eof1InvalidTest struct {
	code  string
	error string
}

// Codes starting with something else other than EF + magic
var notEOFTests = []string{
	// valid: "EF0001010002020004006000AABBCCDD",
	"",
	"FE",                               // invalid first byte
	"FE0001010002020004006000AABBCCDD", // valid except first byte
	"EF",                               // no magic
	"EF01",                             // not correct magic
	"EF0101010002020004006000AABBCCDD", // valid except magic
}

// Codes starting with EF + magic, but the rest is invalid
var eof1InvalidFormatTests = []eof1InvalidTest{
	// valid: {"EF0001010002020004006000AABBCCDD", nil},
	{"EF00", ErrEOF1InvalidVersion.Error()},                                                 // no version
	{"EF0000", ErrEOF1InvalidVersion.Error()},                                               // invalid version
	{"EF0002", ErrEOF1InvalidVersion.Error()},                                               // invalid version
	{"EF0000010002020004006000AABBCCDD", ErrEOF1InvalidVersion.Error()},                     // valid except version
	{"EF0001", ErrEOF1CodeSectionMissing.Error()},                                           // no header
	{"EF000100", ErrEOF1CodeSectionMissing.Error()},                                         // no code section
	{"EF000101", ErrEOF1CodeSectionSizeMissing.Error()},                                     // no code section size
	{"EF00010100", ErrEOF1CodeSectionSizeMissing.Error()},                                   // code section size incomplete
	{"EF0001010002", ErrEOF1InvalidTotalSize.Error()},                                       // no section terminator
	{"EF000101000200", ErrEOF1InvalidTotalSize.Error()},                                     // no code section contents
	{"EF00010100020060", ErrEOF1InvalidTotalSize.Error()},                                   // not complete code section contents
	{"EF0001010002006000DEADBEEF", ErrEOF1InvalidTotalSize.Error()},                         // trailing bytes after code
	{"EF00010100020100020060006000", ErrEOF1MultipleCodeSections.Error()},                   // two code sections
	{"EF000101000000", ErrEOF1EmptyCodeSection.Error()},                                     // 0 size code section
	{"EF000101000002000200AABB", ErrEOF1EmptyCodeSection.Error()},                           // 0 size code section, with non-0 data section
	{"EF000102000401000200AABBCCDD6000", ErrEOF1DataSectionBeforeCodeSection.Error()},       // data section before code section
	{"EF0001020004AABBCCDD", ErrEOF1DataSectionBeforeCodeSection.Error()},                   // data section without code section
	{"EF000101000202", ErrEOF1DataSectionSizeMissing.Error()},                               // no data section size
	{"EF00010100020200", ErrEOF1DataSectionSizeMissing.Error()},                             // data section size incomplete
	{"EF0001010002020004", ErrEOF1InvalidTotalSize.Error()},                                 // no section terminator
	{"EF0001010002020004006000", ErrEOF1InvalidTotalSize.Error()},                           // no data section contents
	{"EF0001010002020004006000AABBCC", ErrEOF1InvalidTotalSize.Error()},                     // not complete data section contents
	{"EF0001010002020004006000AABBCCDDEE", ErrEOF1InvalidTotalSize.Error()},                 // trailing bytes after data
	{"EF0001010002020000006000", ErrEOF1EmptyDataSection.Error()},                           // 0 size data section
	{"EF0001010002020004020004006000AABBCCDDAABBCCDD", ErrEOF1MultipleDataSections.Error()}, // two data sections
	{"EF0001010002030004006000AABBCCDD", ErrEOF1UnknownSection.Error()},                     // section id = 3
}

var eof1InvalidInstructionsTests = []eof1InvalidTest{
	{"EF0001010001000C", ErrEOF1UndefinedInstruction.Error()},                                                             // 0C is undefined instruction
	{"EF000101000100EF", ErrEOF1UndefinedInstruction.Error()},                                                             // EF is undefined instruction
	{"EF00010100010060", ErrEOF1TruncatedImmediate.Error()},                                                               // PUSH1 without data
	{"EF0001010020007F00000000000000000000000000000000000000000000000000000000000000", ErrEOF1TruncatedImmediate.Error()}, // PUSH32 with 31 bytes of data
}

func TestIsEOFCode(t *testing.T) {
	for _, test := range notEOFTests {
		if isEOFCode(common.Hex2Bytes(test)) {
			t.Errorf("code %v expected to be not EOF", test)
		}
	}

	for _, test := range eof1ValidTests {
		if !isEOFCode(common.Hex2Bytes(test.code)) {
			t.Errorf("code %v expected to be EOF", test.code)
		}
	}

	// invalid but still EOF
	for _, test := range eof1InvalidFormatTests {
		if !isEOFCode(common.Hex2Bytes(test.code)) {
			t.Errorf("code %v expected to be EOF", test.code)
		}
	}
}

func TestReadEOF1Header(t *testing.T) {

	for _, test := range eof1ValidTests {
		header, err := readEOF1Header(common.Hex2Bytes(test.code))
		if err != nil {
			t.Errorf("code %v validation failure, error: %v", test.code, err)
		}
		if header.codeSize != test.codeSize {
			t.Errorf("code %v codeSize expected %v, got %v", test.code, test.codeSize, header.codeSize)
		}
		if header.dataSize != test.dataSize {
			t.Errorf("code %v dataSize expected %v, got %v", test.code, test.dataSize, header.dataSize)
		}
	}

	for _, test := range eof1InvalidFormatTests {
		_, err := readEOF1Header(common.Hex2Bytes(test.code))
		if err == nil {
			t.Errorf("code %v expected to be invalid", test.code)
		} else if err.Error() != test.error {
			t.Errorf("code %v expected error: \"%v\" got error: \"%v\"", test.code, test.error, err.Error())
		}
	}
}

func TestValidateEOF(t *testing.T) {

	for _, test := range eof1ValidTests {
		if !validateEOF(common.Hex2Bytes(test.code)) {
			t.Errorf("code %v expected to be valid", test.code)
		}
	}

	for _, test := range eof1InvalidFormatTests {
		if validateEOF(common.Hex2Bytes(test.code)) {
			t.Errorf("code %v expected to be invalid", test.code)
		}
	}
}

func TestReadValidEOF1Header(t *testing.T) {

	for _, test := range eof1ValidTests {
		header := readValidEOF1Header(common.Hex2Bytes(test.code))
		if header.codeSize != test.codeSize {
			t.Errorf("code %v codeSize expected %v, got %v", test.code, test.codeSize, header.codeSize)
		}
		if header.dataSize != test.dataSize {
			t.Errorf("code %v dataSize expected %v, got %v", test.code, test.dataSize, header.dataSize)
		}
	}
}

func TestValidateInstructions(t *testing.T) {
	jt := &londonInstructionSet
	for _, test := range eof1ValidTests {
		code := common.Hex2Bytes(test.code)
		header, err := readEOF1Header(code)
		if err != nil {
			t.Errorf("code %v header validation failure, error: %v", test.code, err)
		}

		err = validateInstructions(code, &header, jt)
		if err != nil {
			t.Errorf("code %v instruction validation failure, error: %v", test.code, err)
		}
	}

	for _, test := range eof1InvalidInstructionsTests {
		code := common.Hex2Bytes(test.code)
		header, err := readEOF1Header(code)
		if err != nil {
			t.Errorf("code %v header validation failure, error: %v", test.code, err)
		}

		err = validateInstructions(code, &header, jt)
		if err == nil {
			t.Errorf("code %v expected to be invalid", test.code)
		} else if err.Error() != test.error {
			t.Errorf("code %v expected error: \"%v\" got error: \"%v\"", test.code, test.error, err.Error())
		}
	}
}

func TestValidateUndefinedInstructions(t *testing.T) {
	jt := &londonInstructionSet
	code := common.Hex2Bytes("EF0001010001000C")
	instrByte := &code[7]
	for opcode := uint16(0); opcode <= 0xff; opcode++ {
		if OpCode(opcode) >= PUSH1 && OpCode(opcode) <= PUSH32 {
			continue
		}

		*instrByte = byte(opcode)
		header, err := readEOF1Header(code)
		if err != nil {
			t.Errorf("code %v header validation failure, error: %v", code, err)
		}

		_, defined := opCodeToString[OpCode(opcode)]

		err = validateInstructions(code, &header, jt)
		if defined {
			if err != nil {
				t.Errorf("code %v instruction validation failure, error: %v", code, err)
			}
		} else {
			if err == nil {
				t.Errorf("opcode %v expected to be invalid", opcode)
			} else if err != ErrEOF1UndefinedInstruction {
				t.Errorf("opcode %v unxpected error: \"%v\"", opcode, err.Error())
			}
		}
	}
}

func TestValidateTruncatedPush(t *testing.T) {
	jt := &londonInstructionSet
	zeroes := [32]byte{}
	code := common.Hex2Bytes("EF0001010001000C")
	for opcode := PUSH1; opcode <= PUSH32; opcode++ {
		requiredBytes := opcode - PUSH1 + 1
		codeTruncated := append(code, zeroes[:requiredBytes-1]...)
		codeTruncated[5] = byte(len(codeTruncated) - 7)
		codeTruncated[7] = byte(opcode)

		header, err := readEOF1Header(codeTruncated)
		if err != nil {
			t.Errorf("code %v header validation failure, error: %v", code, err)
		}

		err = validateInstructions(codeTruncated, &header, jt)
		if err == nil {
			t.Errorf("code %v has truncated PUSH, expected to be invalid", codeTruncated)
		} else if err != ErrEOF1TruncatedImmediate {
			t.Errorf("code %v unexpected validation error: %v", codeTruncated, err)
		}

		codeValid := append(code, zeroes[:requiredBytes]...)
		codeValid[5] = byte(len(codeValid) - 7)
		codeValid[7] = byte(opcode)

		header, err = readEOF1Header(codeValid)
		if err != nil {
			t.Errorf("code %v header validation failure, error: %v", code, err)
		}

		err = validateInstructions(codeValid, &header, jt)
		if err != nil {
			t.Errorf("code %v instruction validation failure, error: %v", code, err)
		}
	}
}
