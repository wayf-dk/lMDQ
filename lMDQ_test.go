package lMDQ

import (
	"log"
	"os"
	"testing"
)

var (
	hashes  =   []string{}
	hub     = MDQ{url: "https://test-phph.test.lan/test-md/WAYF-HUB-PUBLIC.xml", hash: "e0cff78934baa85a4a1b084dcb586fe6bb2f7619"}
	hub_ops = MDQ{url: "https://test-phph.test.lan/MDQ/HUB-OPS/entities/HUB-OPS.xml", hash: "e0cff78934baa85a4a1b084dcb586fe6bb2f7619"}
	edugain = MDQ{url: "https://test-phph.test.lan/test-md/MEC.xml", hash: "e0cff78934baa85a4a1b084dcb586fe6bb2f7619"}
)

func TestMain(m *testing.M) {
	hub.Open("hub.mddb")
	hub_ops.Open("hub_ops.mddb")
	edugain.Open("edugain.mddb")

	os.Exit(m.Run())
}

func getBenchmarkHashes() {
	hash := ""
	rows, err := hub_ops.db.Query("select l.hash from entity e, lookup l where e.id = l.entity_id_fk order by l.hash")
	if err != nil {
		log.Panicln(err)
	}
	defer rows.Close()

	for rows.Next() {
		rows.Scan(&hash)
		hashes = append(hashes, hash)
	}
}

func TestUpdate(t *testing.T) {
    for _, md := range []MDQ{hub, hub_ops, edugain} {
       if err := md.Update(); err != nil {
           log.Println("lMDQ error   ", err)
       }
	}
	// Output: hi
}

func BenchmarkMDQ(b *testing.B) {
    getBenchmarkHashes()
    max := len(hashes)

	for i := 0; i < b.N; i++ {
		hash := hashes[i % max]
		_, _, _ = hub_ops.MDQ("{sha1}" + hash)
	}
}
