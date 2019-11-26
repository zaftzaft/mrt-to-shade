package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/osrg/gobgp/pkg/packet/mrt"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	filename = kingpin.Arg("filename", "mrt file path").Required().String()
	color    = []string{
		"fde725", "eae51a", "d5e21a", "c0df25", "a8db34", "93d741",
		"7fd34e", "6ccd5a", "58c765", "48c16e", "3aba76", "2eb37c",
		"25ab82", "20a386", "1e9c89", "1f948c", "228c8d", "25848e",
		"287d8e", "2b758e", "2e6d8e", "32658e", "365d8d", "3a548c",
		"3e4a89", "424186", "453882", "472e7c", "482374", "48186a",
		"470d60", "440154",
	}
)

func Run() int {
	// Reference: https://github.com/osrg/gobgp/blob/master/cmd/gobgp/mrt.go
	f, err := os.Open(*filename)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	defer f.Close()

	for {
		buf := make([]byte, 12)
		_, err = f.Read(buf)
		if err != nil {
			break
		}

		h := &mrt.MRTHeader{}
		err = h.DecodeFromBytes(buf)
		if err != nil {
			fmt.Println(err)
			return 1
		}

		buf = make([]byte, h.Len)
		_, err = f.Read(buf)
		if err != nil {
			break
		}

		msg, err := mrt.ParseMRTBody(h, buf)
		if err != nil {
			continue
		}

		if h.SubType == mrt.RIB_IPV4_UNICAST.ToUint16() {
			rib := msg.Body.(*mrt.Rib)

			s := strings.Split(rib.Prefix.String(), "/")
			n, err := strconv.Atoi(s[1])
			if err != nil {
				continue
			}

			//fmt.Println(rib.Prefix, "0x26A69A", "64")
			fmt.Printf("%s\t0x%s\t64\n", rib.Prefix, color[n - 1])
		} else {
			continue
		}
	}

	return 0
}

func main() {
	kingpin.Version("0.0.1")
	kingpin.Parse()
	os.Exit(Run())
}
