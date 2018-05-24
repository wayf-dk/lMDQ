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
	Md.Hub = &MDQ{Path: "file:/home/mekhan/wayfhybrid/hybrid-metadata-test.mddb?mode=ro", Table: "HYBRID_HUB"}
	Md.Internal = &MDQ{Path: "file:/home/mekhan/wayfhybrid/hybrid-metadata.mddb?mode=ro", Table: "HYBRID_INTERNAL"}
	Md.ExternalIdP = &MDQ{Path: "file:/home/mekhan/wayfhybrid/hybrid-metadata-test.mddb?mode=ro", Table: "HYBRID_EXTERNAL_IDP"}
	Md.ExternalSP = &MDQ{Path: "file:/home/mekhan/wayfhybrid/hybrid-metadata.mddb?mode=ro", Table: "HYBRID_EXTERNAL_SP"}

	for _, md := range []gosaml.Md{Md.Hub, Md.Internal, Md.ExternalIdP, Md.ExternalSP} {
		err := md.(*MDQ).Open()
		if err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}

func ExampleMDQ() {
	extMetadata, _ := Md.ExternalIdP.MDQ("https://aai-logon.switch.ch/idp/shibboleth")
	printHashedDom(extMetadata)
	intMetadata, _ := Md.Internal.MDQ("https://wayfsp.wayf.dk")
	printHashedDom(intMetadata)
	hubMetadata, _ := Md.Hub.MDQ("https://wayf.wayf.dk")
	printHashedDom(hubMetadata)
	// Output:
	// HOuViozZYV3I9xTnCTMlpRfrAiU=
	// g2R+ZRYDc+mrY6mvgMKaFyn4M/0=
	// bHo3f2bGLC3YWq16SgancRECE04=
}

func ExampleNoMetadata() {
	_, err := Md.ExternalIdP.MDQ("https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth")
	fmt.Println(err)
	// Output:
	// ["cause:Metadata not found","err:Metadata not found","key:https://attribute-viewer.aai.switch.ch/interfederation-test/shibboleth","table:HYBRID_EXTERNAL_IDP"]
}

func ExampleDbget() {
	extMetadata, _ := Md.ExternalIdP.(*MDQ).dbget("https://aai-logon.switch.ch/idp/shibboleth", true)
	printHashedDom(extMetadata)
	// Output:
	// HOuViozZYV3I9xTnCTMlpRfrAiU=
}

func ExampleMDQFilter() {
	_, numberOfTestSPs, _ := Md.Internal.(*MDQ).MDQFilter("/*[not(contains(@entityID, 'birk.wayf.dk/birk.php'))]/*/wayf:wayf[not(wayf:IDPList!='') and wayf:redirect.validate='']/../../md:SPSSODescriptor/..")
	fmt.Println(numberOfTestSPs)
	// Output:
	// 121
}
