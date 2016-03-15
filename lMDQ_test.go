package lMDQ

import (
	"log"
	"os"
	"testing"
)

var (
	hashes       = []string{}
	test_hub     = MDQ{url: "https://test-phph.test.lan/test-md/WAYF-HUB-PUBLIC.xml", hash: "e0cff78934baa85a4a1b084dcb586fe6bb2f7619"}
	test_hub_ops = MDQ{url: "https://test-phph.test.lan/MDQ/HUB-OPS/entities/HUB-OPS.xml", hash: "e0cff78934baa85a4a1b084dcb586fe6bb2f7619"}
	test_edugain = MDQ{url: "https://test-phph.test.lan/test-md/MEC.xml", hash: "e0cff78934baa85a4a1b084dcb586fe6bb2f7619"}
	prod_hub     = MDQ{url: "https://phph.wayf.dk/md/wayf-hub.xml", hash: "f328b1e2b9edeb416403ac70601bc1306f74a836"}
	prod_hub_ops = MDQ{url: "https://phph.wayf.dk/md/HUB.xml", hash: "f328b1e2b9edeb416403ac70601bc1306f74a836"}
	prod_birk    = MDQ{url: "https://phph.wayf.dk/md/birk-idp-public.xml", hash: "f328b1e2b9edeb416403ac70601bc1306f74a836"}
)

func TestMain(m *testing.M) {
	prod_hub.XOpen("prod_hub.mddb")
	prod_hub_ops.XOpen("prod_hub_ops.mddb")
	prod_birk.XOpen("prod_birk.mddb")

	test_hub.XOpen("test_hub.mddb")
	test_hub_ops.XOpen("test_hub_ops.mddb")
	test_edugain.XOpen("test_edugain.mddb")

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

func TestUpdate(t *testing.T) {
	for _, md := range []MDQ{test_hub, test_hub_ops, test_edugain, prod_hub, prod_hub_ops, prod_birk} {
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
		hash := hashes[i%max]
		_, _ = prod_hub_ops.MDQ("{sha1}" + hash)
	}
}
