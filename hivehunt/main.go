package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"golang.org/x/text/encoding/charmap"
	"www.velocidex.com/golang/regparser"
)

type RegValue struct {
	Name string      `json:"name"`
	Type uint32      `json:"type"`
	Data interface{} `json:"data"`
}

type RegKey struct {
	Path    string             `json:"path"`
	Values  []RegValue         `json:"values,omitempty"`
	SubKeys map[string]*RegKey `json:"subkeys,omitempty"`
}

func decodeWin1251(data []byte) string {
	str, err := charmap.Windows1251.NewDecoder().Bytes(data)
	if err != nil {
		return string(data)
	}
	return string(str)
}

func cleanString(s string) string {
	return strings.TrimRight(s, "\u0000")
}

func convertValue(val *regparser.CM_KEY_VALUE) interface{} {
	vd := val.ValueData()

	if vd.String != "" {
		return cleanString(vd.String)
	}

	if len(vd.MultiSz) > 0 {
		cleaned := make([]string, len(vd.MultiSz))
		for i, s := range vd.MultiSz {
			cleaned[i] = cleanString(s)
		}
		return cleaned
	}

	if vd.Uint64 != 0 {
		return vd.Uint64
	}

	if len(vd.Data) > 0 {
		decoded := cleanString(decodeWin1251(vd.Data))
		if decoded != "" && len(decoded) >= len(vd.Data)/2 {
			return decoded
		}
		return base64.StdEncoding.EncodeToString(vd.Data)
	}

	return nil
}

func parseKey(key *regparser.CM_KEY_NODE, path string) *RegKey {
	rk := &RegKey{
		Path:    path,
		Values:  []RegValue{},
		SubKeys: map[string]*RegKey{},
	}

	for _, val := range key.Values() {
		rk.Values = append(rk.Values, RegValue{
			Name: cleanString(val.ValueName()),
			Type: val.Type(),
			Data: convertValue(val),
		})
	}

	for _, sub := range key.Subkeys() {
		subName := cleanString(sub.Name())
		subPath := path + "\\" + subName
		rk.SubKeys[subName] = parseKey(sub, subPath)
	}

	return rk
}

func main() {
	if len(os.Args) != 3 {
		fmt.Println("Usage: hivehunt <Path To Hive> <Output JSON File>")
		return
	}

	filePath := os.Args[1]
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Printf("Error opening hive: %v\n", err)
		return
	}
	defer file.Close()

	hive, err := regparser.NewRegistry(file)
	if err != nil {
		fmt.Printf("Error parsing hive: %v\n", err)
		return
	}

	root := hive.OpenKey("")
	if root == nil {
		fmt.Println("Could not locate root key")
		return
	}

	tree := parseKey(root, "HKCU")

	jsonData, err := json.MarshalIndent(tree, "", "  ")
	if err != nil {
		fmt.Printf("Error encoding JSON: %v\n", err)
		return
	}

	err = os.WriteFile(os.Args[2], jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing JSON file: %v\n", err)
		return
	}

	fmt.Printf("Successfully converted %s to %s\n", os.Args[1], os.Args[2])
}
