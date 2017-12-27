// Copyright 2017 Alexis Gryta. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

package pcapnggo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"bufio"
	"compress/gzip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Reader wraps an underlying io.Reader to read packet data in PCAP-NG
// format.  See http://wiki.wireshark.org/Development/LibpcapFileFormat
// for information on the file format.
//
// We currenty read v1.0 file format with
// timestamp resolution in little-endian and big-endian encoding.
//
// If the PCAP data is gzip compressed it is transparently uncompressed
// by wrapping the given io.Reader with a gzip.Reader.
type Reader struct {
	Section
	r              io.Reader
	// timezone
	// sigfigs
	// reusable buffer
	buf [16]byte
}

type Section struct {
	byteOrder      binary.ByteOrder
	versionMajor   uint16
	versionMinor   uint16
	sectionLength  int64
	//options[]
	i []NwIfc
}

type NwIfc struct {
	linkType layers.LinkType
	snaplen  uint32
	//options[]
}

// blockType is an enumeration of block types for PCAPNG format, and acts as a decoder for any
// block type it supports.
type BlockType uint32

const (
	// According to PCAP Next Generation Dump File Format:
	// https://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html
	BlockTypeSectionHeader         BlockType = 0x0A0D0D0A
	BlockTypeInterfaceDescription  BlockType = 0x00000001
	BlockTypeEnhancedPacket        BlockType = 0x00000006
	BlockTypeSimplePacket          BlockType = 0x00000003
	BlockTypeNameResolution        BlockType = 0x00000004
	BlockTypeInterfaceStatistics   BlockType = 0x00000005
	BlockTypeCustomAllowCopy       BlockType = 0x00000BAD
	BlockTypeCustomNoCopy          BlockType = 0x40000BAD
)

const magicNumber = 0x1A2B3C4D
const magicNumberBigendian = 0x4D3C2B1A


const magicNanoseconds = 0xA1B23C4D
const magicMicrosecondsBigendian = 0xD4C3B2A1
const magicNanosecondsBigendian = 0x4D3CB2A1

const magicGzip1 = 0x1f
const magicGzip2 = 0x8b


const versionMajor = 1
const versionMinor = 0

// This function is used to read from the reader
func (r *Reader) readFull(buf []byte) (n int, err error) {
	if n, err = io.ReadFull(r.r, buf); err != nil {
		return err
	} else if n < len(buf) {
		return errors.New("Not enough data to read")
	}
}

// NewReader returns a new reader object, for reading packet data from
// the given reader. The reader must be open and header data is
// read from it at this point.
// If the file format is not supported an error is returned
//
//  // Create new reader:
//  f, _ := os.Open("/tmp/file.pcap")
//  defer f.Close()
//  r, err := NewReader(f)
//  data, ci, err := r.ReadPacketData()
func NewReader(r io.Reader) (*Reader, error) {
	ret := Reader{r: r}
	if err := ret.readHeader(); err != nil {
		return nil, err
	}
	return &ret, nil
}

func (r *Reader) readHeader() error {
	br := bufio.NewReader(r.r)
	gzipMagic, err := br.Peek(2)
	if err != nil {
		return err
	}

	if gzipMagic[0] == magicGzip1 && gzipMagic[1] == magicGzip2 {
		if r.r, err = gzip.NewReader(br); err != nil {
			return err
		}
	} else {
		r.r = br
	}

	buf := make([]byte, 4)
	bt , err := r.readFull(buf)
	if err != nil {
		return err
	}
	if uint32(bt) == BlockTypeSectionHeader {
		if err := r.readSectionHeaderBlock(); err != nil {
			return err
		}
	} else {
		return fmt.Errorf("First block isn't a section header block %x", bt)
	}

	return nil
}

// ReadPacketData reads blocks from file till the next data packet.
func (r *Reader) ReadPacketData() (data []byte, ci gopacket.CaptureInfo, err error) {
	buf := make([]byte, 4)
	for {
		// First read the block type
		if _ , err = r.readFull(buf) ; err != nil {
			return
		}

		if uint32(buf[0:4]) == BlockTypeSectionHeader {
			if err = r.readSectionHeaderBlock(); err != nil {
				continue
			}
		}

		switch r.byteOrder.Uint32(buf[0:4]) {
		case BlockTypeInterfaceDescription:
			fmt.Println("Found Interface Description Block")
			if err = r.readInterfaceDescriptionBlock(); err != nil {
				return
			}
			continue
		case BlockTypeEnhancedPacket:
			fmt.Println("Found Enhanced Packet Block")
			if data, ci, err = r.readEnhancedPacketBlock(); err != nil {
				return
			}
			return
		case BlockTypeSimplePacket:
			fmt.Println("Found Simple Packet Block")
			if data, ci, err = r.readSimplePacketBlock(); err != nil {
				return
			}
			return
		default:
			fmt.Println("Found Unknown/Experimental/Obsolete Block")
			if err = r.readUnknownBlock(); err != nil {
				return
			}
			continue
		}
	}
	return
}

// ######################################################################################
//         methods
// ######################################################################################

func (r *Reader) readUnknownBlock() (error) {
	buf := make([]byte, 4)
	if _ , err = r.readFull(buf) ; err != nil {
		return
	}
	lastPart := int(buf[0:4]) - 4
	buf := make([]byte, lastPart)
	if _ , err = r.readFull(buf) ; err != nil {
		return
	}
	return nil
}

func (r *Reader) readSimplePacketBlock() (data []byte, ci gopacket.CaptureInfo, err error) {

	buf := make([]byte, 2*4)
	if _ , err = r.readFull(buf) ; err != nil {
		return
	}
	// left to read: total length - the 4B Block type word - what we read
	lastPart := int(buf[0:4]) - 4 - 2*4

	ci.CaptureLength = int(r.byteOrder.Uint32(r.buf[4:8]))
	ci.Length = ci.CaptureLength

	// Read Packet Data + Options + BlockTypeLength word
	buf := make([]byte, lastPart)
	if _ , err = r.readFull(buf) ; err != nil {
		return
	}

	data = make([]byte, ci.CaptureLength)
	data = buf[0:ci.CaptureLength]

	// No options

	return
}

func (r *Reader) readEnhancedPacketBlock() (data []byte, ci gopacket.CaptureInfo, err error) {

	buf := make([]byte, 6*4)
	if _ , err = r.readFull(buf) ; err != nil {
		return
	}
	// left to read: total length - the 4B Block type word - what we read
	lastPart := int(buf[0:4]) - 4 - 6*4

	ci.InterfaceIndex = int(r.byteOrder.Uint32(buf[4:8]))

	// ~~~~~~~~~~~ TO DO AFTER the options of the interface desc block
	timestamp := r.byteOrder.Uint64(buf[8:20])
	ci.Timestamp = timestamp
	// ~~~~~~~~~~~ TO DO AFTER the options of the interface desc block

	ci.CaptureLength = int(r.byteOrder.Uint32(buf[20:24]))
	ci.Length = int(r.byteOrder.Uint32(buf[24:28]))

	// Read Packet Data + Options + BlockTypeLength word
	buf := make([]byte, lastPart)
	if _ , err = r.readFull(buf) ; err != nil {
		return
	}

	data = make([]byte, ci.CaptureLength)
	data = buf[0:ci.CaptureLength]

	// Here process options

	return
}

func (r *Reader) readSectionHeaderBlock() (error) {
	// Read Block Total Length with the Byte-Order Magic
	buf := make([]byte, 8)
	if _ , err := r.readFull(buf) ; err != nil {
		return err
	}

	if magic := binary.LittleEndian.Uint32(buf[0:4]); magic == magicNumber {
		r.byteOrder = binary.LittleEndian
	} else if magic == magicNumberBigendian {
		r.byteOrder = binary.BigEndian
	} else {
		return fmt.Errorf("Unknown magic %x", magic)
	}

	// Start to jump the blockType
	lastPart := int(buf[4:8])-8-4
	buf := make([]byte, lastPart)
	if _ , err := r.readFull(buf) ; err != nil {
		return err
	}

	if r.versionMajor = r.byteOrder.Uint16(buf[0:3]); r.versionMajor != versionMajor {
		return fmt.Errorf("Unknown major version %d", r.versionMajor)
	}
	if r.versionMinor = r.byteOrder.Uint16(buf[2:4]); r.versionMinor != versionMinor {
		return fmt.Errorf("Unknown minor version %d", r.versionMinor)
	}

	r.sectionLength = int64(r.byteOrder.Uint64(buf[4:12]))

	// Here process options

	return nil
}

func (r *Reader) readInterfaceDescriptionBlock() (error) {
	//   +---------------------------------------------------------------+
	// 4 |                      Block Total Length                       |
	//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	buf := make([]byte, 4)
	if _ , err := r.readFull(buf) ; err != nil {
		return err
	}

	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |           LinkType            |           Reserved            |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                            SnapLen                            |
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  /                                                               /
	//  /                      Options (variable)                       /
	//  /                                                               /
	//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	//  |                      Block Total Length                       |
	//  +---------------------------------------------------------------+
	lastPartLen := int(buf[0:4])-8
	buf := make([]byte, lastPartLen)
	if _ , err := r.readFull(buf) ; err != nil {
		return err
	}
	linkType := layers.LinkType((r.byteOrder.Uint32(buf[0:2])))
	snapLen := r.byteOrder.Uint32(buf[8:12])
	r.i = append(r.i, NwIfc{linkType, snapLen})

	// Here process options

	return nil
}

// ########################
//         getters
// ########################

// LinkType returns network, as a layers.LinkType.
func (r *Reader) LinkType(ifc int) layers.LinkType {
	return r.i[ifc].linkType
}

// Snaplen returns the snapshot length of the capture file.
func (r *Reader) Snaplen(ifc int) uint32 {
	return r.i[ifc].snaplen
}

// Reader formater
func (r *Reader) String() string {
	var objstring string
	objstring = fmt.Sprintf("Pcap-NG File  maj: %x min: %x\n", r.versionMajor, r.versionMinor)
	for n := 0 ; i<len(r.i) ; n++ {
		objstring +=  fmt.Sprintf("   Interface #%2d: snaplen: %d linktype: %s\n",
			n, r.i[n].snaplen, r.i[n].linkType)
	}
	return objstring
}