package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
)

var lnkCLSID = []byte{
	0x01, 0x14, 0x02, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0xC0, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x46,
}

type BinaryReader struct {
	data []byte
	pos  uint32
}

func NewBinaryReader(data []byte) *BinaryReader {
	return &BinaryReader{data: data}
}

func (r *BinaryReader) read(v any) error {
	size := binary.Size(v)
	if int(r.pos)+size > len(r.data) {
		return errors.New("unexpected EOF")
	}
	buf := bytes.NewReader(r.data[r.pos : r.pos+uint32(size)])
	err := binary.Read(buf, binary.LittleEndian, v)
	r.pos += uint32(size)
	return err
}

func (r *BinaryReader) readBytes(n uint32) ([]byte, error) {
	if int(r.pos+n) > len(r.data) {
		return nil, errors.New("unexpected EOF")
	}
	b := r.data[r.pos : r.pos+n]
	r.pos += n
	return b, nil
}

func (r *BinaryReader) seek(pos uint32) error {
	if int(pos) > len(r.data) {
		return errors.New("seek beyond EOF")
	}
	r.pos = pos
	return nil
}

func filetimeToTime(ft uint64) *time.Time {
	if ft == 0 {
		return nil
	}
	unix := int64((ft - 116444736000000000) / 10000000)
	t := time.Unix(unix, 0).UTC()
	return &t
}

func readCString(r *BinaryReader) (string, error) {
	var out []byte
	for {
		b, err := r.readBytes(1)
		if err != nil {
			return "", err
		}
		if b[0] == 0x00 {
			break
		}
		out = append(out, b[0])
	}
	return string(out), nil
}

func readString(r *BinaryReader, unicode bool) (string, error) {
	var length uint16
	if err := r.read(&length); err != nil {
		return "", err
	}

	if unicode {
		b, err := r.readBytes(uint32(length) * 2)
		if err != nil {
			return "", err
		}
		return string(bytes.TrimRight(b, "\x00")), nil
	}

	b, err := r.readBytes(uint32(length))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func parseHeader(r *BinaryReader) (map[string]any, uint32, error) {
	h := make(map[string]any)

	var headerSize uint32
	if err := r.read(&headerSize); err != nil {
		return nil, 0, err
	}

	clsid, err := r.readBytes(16)
	if err != nil {
		return nil, 0, err
	}

	if headerSize != 0x4C {
		return nil, 0, errors.New("invalid header size")
	}
	if !bytes.Equal(clsid, lnkCLSID) {
		return nil, 0, errors.New("invalid CLSID")
	}

	var linkFlags uint32
	var fileAttr uint32
	var ctime, atime, wtime uint64
	var fileSize uint32
	var iconIndex int32
	var showCmd uint32
	var hotKey uint16

	r.read(&linkFlags)
	r.read(&fileAttr)
	r.read(&ctime)
	r.read(&atime)
	r.read(&wtime)
	r.read(&fileSize)
	r.read(&iconIndex)
	r.read(&showCmd)
	r.read(&hotKey)

	r.pos += 10

	h["CreationTime"] = filetimeToTime(ctime)
	h["AccessTime"] = filetimeToTime(atime)
	h["WriteTime"] = filetimeToTime(wtime)
	h["FileSize"] = fileSize
	h["IconIndex"] = iconIndex
	h["ShowCommand"] = showCmd
	h["HotKey"] = hotKey
	h["FileAttributes"] = fileAttr

	return h, linkFlags, nil
}

func parseLinkTargetIDList(r *BinaryReader) error {
	var size uint16
	if err := r.read(&size); err != nil {
		return err
	}
	data, err := r.readBytes(uint32(size))
	if err != nil {
		return err
	}
	if !bytes.HasSuffix(data, []byte{0x00, 0x00}) {
		return errors.New("invalid IDList terminator")
	}
	return nil
}

func parseLinkInfo(r *BinaryReader) (map[string]string, error) {
	start := r.pos

	var size, headerSize, flags uint32
	var volOff, localOff, netOff, commonOff uint32

	r.read(&size)
	r.read(&headerSize)
	r.read(&flags)
	r.read(&volOff)
	r.read(&localOff)
	r.read(&netOff)
	r.read(&commonOff)

	out := make(map[string]string)

	if localOff != 0 {
		r.seek(start + localOff)
		s, _ := readCString(r)
		out["LocalBasePath"] = s
	}

	if commonOff != 0 {
		r.seek(start + commonOff)
		s, _ := readCString(r)
		out["CommonPathSuffix"] = s
	}

	r.seek(start + size)
	return out, nil
}

func skipExtraData(r *BinaryReader) error {
	for {
		var size uint32
		if err := r.read(&size); err != nil {
			return err
		}
		if size == 0 {
			break
		}
		r.pos += size - 4
	}
	return nil
}

func field(name string, value any) {
	fmt.Printf("\t%-28s: %v\n", name, value)
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: lnkparse <file.lnk>")
		return
	}

	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	r := NewBinaryReader(data)

	header, flags, err := parseHeader(r)
	if err != nil {
		fmt.Println("Parse error:", err)
		return
	}

	unicode := flags&0x80 != 0

	if flags&0x01 != 0 {
		parseLinkTargetIDList(r)
	}

	var linkInfo map[string]string
	if flags&0x02 != 0 {
		linkInfo, _ = parseLinkInfo(r)
	}

	strings := make(map[string]string)
	if flags&0x04 != 0 {
		strings["Name"], _ = readString(r, unicode)
	}
	if flags&0x08 != 0 {
		strings["RelativePath"], _ = readString(r, unicode)
	}
	if flags&0x10 != 0 {
		strings["WorkingDirectory"], _ = readString(r, unicode)
	}
	if flags&0x20 != 0 {
		strings["Arguments"], _ = readString(r, unicode)
	}
	if flags&0x40 != 0 {
		strings["IconLocation"], _ = readString(r, unicode)
	}

	skipExtraData(r)

	fmt.Println("Link information:")
	field("CreationTime", header["CreationTime"])
	field("AccessTime", header["AccessTime"])
	field("WriteTime", header["WriteTime"])
	field("FileSize", header["FileSize"])
	field("IconIndex", header["IconIndex"])
	field("ShowCommand", header["ShowCommand"])
	field("HotKey", header["HotKey"])
	field("FileAttributes", header["FileAttributes"])

	if len(linkInfo) > 0 {
		fmt.Println("\nTarget Path:")
		field("LocalBasePath", linkInfo["LocalBasePath"])
		field("CommonPathSuffix", linkInfo["CommonPathSuffix"])
	}

	if len(strings) > 0 {
		fmt.Println("\nStringData:")
		for k, v := range strings {
			field(k, v)
		}
	}
}
