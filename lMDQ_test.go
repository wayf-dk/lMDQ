package lMDQ

import (
	"log"
	"os"
	"testing"
)

var (
	hashes                                                                  = []string{}
	test_hub, test_hub_ops, test_edugain, prod_hub, prod_hub_ops, prod_birk *MDQ
)

func TestMain(m *testing.M) {
	prod_hub, _ = Open("prod_hub.mddb")
	prod_hub_ops, _ = Open("prod_hub_ops.mddb")
	prod_birk, _ = Open("prod_birk.mddb")

	test_hub, _ = Open("test_hub.mddb")
	test_hub_ops, _ = Open("test_hub_ops.mddb")
	test_edugain, _ = Open("test_edugain.mddb")

	os.Exit(m.Run())
}

func getBenchmarkHashes() {
	hash := ""
	rows, err := prod_hub_ops.db.Query("select l.hash from entity e, lookup l where e.id = l.entity_id_fk order by l.hash")
	if err != nil {
		log.Panicln(err)
	}
	defer rows.Close()

	for rows.Next() {
		rows.Scan(&hash)
		hashes = append(hashes, hash)
	}
}

func TestAll(t *testing.T) {
	xp, err := test_hub_ops.MDQ("")
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(xp.Doc.Dump(true))
}

func BenchmarkMDQ(b *testing.B) {
	getBenchmarkHashes()
	max := len(hashes)

	for i := 0; i < b.N; i++ {
		hash := hashes[i%max]
		_, _ = prod_hub_ops.MDQ("{sha1}" + hash)
	}
}
