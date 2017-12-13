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

func xTestMain(m *testing.M) {

	os.Exit(m.Run())
}

func xgetBenchmarkHashes() {
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

func xTestAll(t *testing.T) {
	xp, err := test_hub_ops.MDQ("")
	if err != nil {
		log.Fatalln(err)
	}
	log.Println(xp.Doc.Dump(true))
}

func xBenchmarkMDQ(b *testing.B) {
	xgetBenchmarkHashes()
	max := len(hashes)

	for i := 0; i < b.N; i++ {
		hash := hashes[i%max]
		_, _ = prod_hub_ops.MDQ("{sha1}" + hash)
	}
}
