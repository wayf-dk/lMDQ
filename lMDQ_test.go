package lMDQ

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"os"
	"testing"
)

type (
	MdSets struct {
		Hub, Internal, ExternalIdP, ExternalSP gosaml.Md
	}
)

var (
	Md MdSets
)

func printHashedDom(xp *goxml.Xp) {
	hash := sha1.Sum([]byte(xp.C14n(nil, "")))
	fmt.Println(base64.StdEncoding.EncodeToString(append(hash[:])))
}

// Need to change Path. So it should work for everyone.
func TestMain(m *testing.M) {
	Md.Hub = &MDQ{Path: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_HUB"}
	Md.Internal = &MDQ{Path: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_INTERNAL"}
	Md.ExternalIdP = &MDQ{Path: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_EXTERNAL_IDP"}
	Md.ExternalSP = &MDQ{Path: "file:testdata/test-metadata.mddb?mode=ro", Table: "HYBRID_EXTERNAL_SP"}

	for _, md := range []gosaml.Md{Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP} {
		err := md.(*MDQ).Open()
		if err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}

func ExampleMDQ() {
	extMetadata, _ := Md.ExternalIdP.MDQ("https://birk.wayf.dk/birk.php/orphanage.wayf.dk")
	printHashedDom(extMetadata)
	intMetadata, _ := Md.Internal.MDQ("https://wayf.aau.dk")
	printHashedDom(intMetadata)
	hubMetadata, _ := Md.Hub.MDQ("https://wayf.wayf.dk")
	printHashedDom(hubMetadata)
	// Output:
	// yo8u3VPVo5vgPg+0WazNE6Dhd24=
	// umTNPHT/1/jUYF7zVjBFP3CCFtY=
	// OnvR35f3xX+93gu2oIT8stFU8Xc=
}

func ExampleNoMetadata() {
	_, err := Md.ExternalIdP.MDQ("https://exampple.com")
	fmt.Println(err)
	// Output:
	// ["cause:Metadata not found","err:Metadata not found","key:https://exampple.com","table:HYBRID_EXTERNAL_IDP"]
}

func ExampleDbget() {
	extMetadata, _ := Md.ExternalIdP.(*MDQ).dbget("https://birk.wayf.dk/birk.php/sso.sdu.dk/wayf", true)
	printHashedDom(extMetadata)
	// Output:
	// q+7HfLzgSYoreRyWO+L3uyHgAVU=
}

func ExampleMDQFilter() {
	_, numberOfTestSPs, _ := Md.Internal.(*MDQ).MDQFilter("/*[not(contains(@entityID, 'https://wayf.aau.dk'))]/*/wayf:wayf[not(wayf:IDPList!='') and wayf:redirect.validate='']/../../md:SPSSODescriptor/..")
	fmt.Println(numberOfTestSPs)
	// Output:
	// 0
}
