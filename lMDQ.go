/*  lMDQ is a MDQ server that caches metadata locally so it's local clients can lookup
    pre-checked metadata and not depend on a working connection to a remote MDQ server.

    It uses SQLite as it's datastore and allows lookup by either entityID or Location.
    The latter is used by WAYF for it's mass hosting services BIRK and KRIB.

    It can also be used as a library for just looking up metadata inside a go program.

    Or a client can use the SQLite database directly using the following query:

		"select e.md, e.hash from entity e, lookup l where l.hash = $1 and l.entity_id_fk = e.id and e.validuntil >= $2"

    where $1 is the lowercase hex sha1 of the entityID or location without the {sha1} prefix
    $2 is the current epoch.

    to-do:
        √ caching interface
          invalidate cache ???
*/

package lMDQ

import (
	"crypto"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
    "github.com/aryann/difflib"
	_ "github.com/mattn/go-sqlite3"
	"github.com/wayf-dk/goxml"
	"github.com/wayf-dk/gosaml"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	//"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	// pragma wal ???
	lMDQSchema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS entity
(
    id INTEGER PRIMARY KEY,
    entityid text not null unique,
    md text NOT NULL,
    hash text NOT NULL
);

CREATE TABLE IF NOT EXISTS lookup
(
    id INTEGER PRIMARY KEY,
    hash text NOT NULL,
    entity_id_fk INTEGER,
    unique(hash, entity_id_fk),
    FOREIGN KEY(entity_id_fk) REFERENCES entity(id) on delete cascade
);

CREATE TABLE IF NOT EXISTS validuntil
(
    id integer primary key default 1,
    validuntil integer not null default 0
);

CREATE INDEX if not exists lookupbyhash ON lookup(hash);
insert or ignore into validuntil (id) values (1);
`
)

type (
	EntityRec struct {
		id       int64
		entityid string
		hash     string
	}

	MDQ struct {
		db              *sql.DB
		stmt            *sql.Stmt
		Url, Hash, Path, MetadataSchemaPath string
		Cache           map[string]*MdXp
	    Lock            sync.Mutex
	    Silent          bool
	}

	MdXp struct {
		*goxml.Xp
		created time.Time
	}
)

var (
	cacheduration = time.Minute * 1

	indextargets = []string{
		"./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location",
		"./md:SPSSODescriptor/md:AssertionConsumerService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST']/@Location",
	}
)

func init() {

}

func Cmp(feed1, feed2 MDQ) {
    ents1, _ := feed1.getEntityList()
    ents2, _ := feed2.getEntityList()
//    len1 := len(ents1)
    len2 := len(ents2)
    seen := 0
    for id, _ := range ents1 {
        x1, _ := feed1.MDQ(id)
        x2, _ := feed2.MDQ(id)
        str1 := x1.Doc.Dump(true)
        str2 := x2.Doc.Dump(true)
        hash1 := hex.EncodeToString(goxml.Hash(crypto.SHA1, str1))
        hash2 := hex.EncodeToString(goxml.Hash(crypto.SHA1, str2))
        if hash1 == hash2 {
            fmt.Println("OK ", id)
        } else {
            fmt.Println("NOT", id)
            diffs := difflib.Diff(strings.Split(str1, "\n"), strings.Split(str2, "\n"))
            for _, diff := range diffs {
                if diff.Delta != difflib.Common {
                    fmt.Println(diff)
                }
            }
            fmt.Println()
        }
        seen++
    }
    fmt.Println("Number of entities: ", seen, len2)
}

func (xp *MdXp) Valid(duration time.Duration) bool {
	since := time.Since(xp.created)
	//log.Println(since, duration, since  < duration)
	return since < duration
}

func Open(path string) (mdq *MDQ, err error) {
    mdq = new(MDQ)
    return mdq, mdq.Open(path)
}

func (mdq *MDQ) Open(path string) (err error) {
    mdq.Cache = make(map[string]*MdXp)
	mdq.Path = path
	mdq.db, err = sql.Open("sqlite3", path)
	if err != nil {
		return
	}

	return
}

// MDQ looks up an entity using the supplied feed and key.
// The key can be an entityID or a location, optionally in {sha1} format
// It returns a non nil err if the entity is not found
// and the metadata and a hash/etag over the content if it is.
// The hash can be used to decide if a cached dom object is still valid,
// This might be an optimization as the database lookup is much faster that the parsing.
func (mdq *MDQ) MDQ(key string) (xp *goxml.Xp, err error) {
    return mdq.dbget(key, true)
}

func (mdq *MDQ) dbget(key string, cache bool) (xp *goxml.Xp, err error) {
    if mdq.stmt == nil {
        mdq.stmt, err = mdq.db.Prepare(`select e.md from entity e, lookup l, validuntil v
        where l.hash = $1 and l.entity_id_fk = e.id and v.validuntil >= $2`)
        if err != nil {
            return
        }
    }

	k := key
	const prefix = "{sha1}"
	if strings.HasPrefix(key, prefix) {
		key = key[6:]
	} else {
		key = hex.EncodeToString(goxml.Hash(crypto.SHA1, key))
	}

	mdq.Lock.Lock()
	defer mdq.Lock.Unlock()
	cachedxp := mdq.Cache[key]
	if cachedxp != nil && cachedxp.Valid(cacheduration) {
		xp = cachedxp.Xp.CpXp()
		return
	}

	var xml []byte
	err = mdq.stmt.QueryRow(key, time.Now().Unix()).Scan(&xml)
	if err != nil {
		//log.Println("query", mdq.path, k, key, err, string(xml))
		err = fmt.Errorf("Metadata not found for entity: %s", k)
		//debug.PrintStack()
		return
	}
//	xp = goxml.NewXp((string)(gosaml.Inflate(xml)))
	xp = goxml.NewXp(string(xml))
    if cache {
	    mdxp := new(MdXp)
	    mdxp.Xp = xp
	    mdxp.created = time.Now()
	    mdq.Cache[key] = mdxp
	}
	return
}

/**
    One at a time - not that fast - only use for testing
    Filtered by xpath for testing purposes
*/
func (mdq *MDQ) MDQFilter(xpathfilter string) (xp *goxml.Xp, numberOfEntities int, err error) {
	recs, err := mdq.getEntityList()
	if err != nil {
		return
	}

    // get the entities into an ordered slice
    index := make([]string, len(recs))
    i := 0
    for k, _ := range recs {
        index[i] = k
        i++
    }
    sort.Strings(index)

	//log.Println(xpathfilter)
	xp = goxml.NewXp(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" />`)

    root, _ := xp.Doc.DocumentElement()
	for _, entityID := range index {
	    ent, _ := mdq.dbget(entityID, false)

	    if xpathfilter == "" || len(ent.Query(nil, xpathfilter)) > 0 {
	        entity, _ := ent.Doc.DocumentElement()
            root.AddChild(xp.CopyNode(entity, 1))
            numberOfEntities++
        }
	}
	return
}

func (mdq *MDQ) xUpdate() (err error) {
	start := time.Now()
	log.Println("lMDQ updating", mdq.Url, mdq.Path)
	var md []byte
	if md, err = get(mdq.Url); err != nil {
		return
	}

	fp, err := os.OpenFile(mdq.Path, os.O_RDWR|os.O_CREATE, os.ModePerm)

	if err != nil {
		return err
	}

	defer fp.Close()

	_, err = fp.Write(md)

	log.Printf("lMDQ finished duration: %.1f", time.Since(start).Seconds())

	return err
}

func (mdq *MDQ) Update() (err error) {
	start := time.Now()
	log.Println("lMDQ updating", mdq.Url, mdq.Path)

	_, err = mdq.db.Exec(lMDQSchema)
	if err != nil {
		return
	}

	recs, err := mdq.getEntityList()
	if err != nil {
		return err
	}
	var md []byte
	if md, err = get(mdq.Url); err != nil {
		return
	}

	dom := goxml.NewXp(string(md))

	if errs, err := dom.SchemaValidate(mdq.MetadataSchemaPath); err != nil {
		log.Println("feed", "SchemaError", err, errs)
		return err
	}

	certificate := dom.Query(nil, "/*/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
	if len(certificate) != 1 {
		err = errors.New("Metadata not signed")
		return
	}
	keyname, key, err := gosaml.PublicKeyInfo(certificate[0].NodeValue())

	if err != nil {
		return
	}

	ok := dom.VerifySignature(nil, key)
	if ok != nil || keyname != mdq.Hash {
		return fmt.Errorf("Signature check failed. Signature %s, %s = %s", ok, keyname, mdq.Hash)
	}

	tx, err := mdq.db.Begin()
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			tx.Rollback()
			return
		}
		err = tx.Commit()
	}()

	entityInsertStmt, err := tx.Prepare("insert into entity (entityid, md, hash) values ($1, $2, $3)")
	if err != nil {
		return
	}
	defer entityInsertStmt.Close()

	lookupInsertStmt, err := tx.Prepare("insert or ignore into lookup (hash, entity_id_fk) values (?, ?)")
	if err != nil {
		return err
	}
	defer lookupInsertStmt.Close()

	entityDeleteStmt, err := tx.Prepare("delete from entity where id = $1")
	if err != nil {
		return err
	}
	defer entityDeleteStmt.Close()

	vu, err := time.Parse(time.RFC3339Nano, dom.Query1(nil, "@validUntil"))
	if err != nil {
		return err
	}
	validUntil := vu.Unix()

	var new, updated, nochange, deleted int
	seen := map[string]bool{}

	entities := dom.Query(nil, "./md:EntityDescriptor | /md:EntityDescriptor")
	for _, entity := range entities {
		entityID := dom.Query1(entity, "@entityID")
		if seen[entityID] {
			log.Printf("lMDQ duplicate entityID: %s", entityID)
			continue
		}
        seen[entityID] = true
		md := goxml.NewXpFromNode(entity).Doc.Dump(false)
		rec := recs[entityID]
		id := rec.id
		hash := hex.EncodeToString(goxml.Hash(crypto.SHA1, md))
		oldhash := rec.hash
		if rec.hash == hash { // no changes
			delete(recs, entityID) // remove so it won't be deleted
			nochange++
			continue
		} else if oldhash != "" { // update is delete + insert - then the cascading delete will also delete the potential stale lookup entries
			_, err = entityDeleteStmt.Exec(rec.id)
			if err != nil {
				return
			}
			updated++
			log.Printf("lMDQ updated entityID: %s", entityID)
			delete(recs, entityID) // updated - remove so it won't be deleted
		} else {
			new++
			if !mdq.Silent {
			    log.Printf("lMDQ new entityID: %s", entityID)
			}
		}
		var res sql.Result
		res, err = entityInsertStmt.Exec(entityID, md, hash)
		if err != nil {
			return err
		}

		id, _ = res.LastInsertId()

		_, err = lookupInsertStmt.Exec(hex.EncodeToString(goxml.Hash(crypto.SHA1, entityID)), id)
		if err != nil {
			return
		}

		for _, target := range indextargets {
			locations := dom.Query(entity, target)
			for i, location := range locations {
			    if !mdq.Silent {
				    log.Println(i, location.NodeValue())
				}
				_, err = lookupInsertStmt.Exec(hex.EncodeToString(goxml.Hash(crypto.SHA1, location.NodeValue())), id)
				if err != nil {
					return
				}
			}
		}
	}
	for entid, ent := range recs { // delete entities no longer in feed
		_, err = entityDeleteStmt.Exec(ent.id)
		if err != nil {
			return
		}
		deleted++
		log.Printf("lMDQ deleted entityID: %s", entid)
	}

	_, err = tx.Exec("update validuntil set validuntil = $1 where id = 1", validUntil)
	if err != nil {
		return
	}

	log.Printf("lMDQ finished %d new, %d updated, %d unchanged, %d deleted validUntil: %s duration: %.1f",
		new, updated, nochange, deleted, time.Unix(validUntil, 0).Format(time.RFC3339), time.Since(start).Seconds())
	return
}

// getEntityList returns a map keyed by entityIDs for the
// current entities in the database
func (mdq *MDQ) getEntityList() (entities map[string]EntityRec, err error) {

	entities = make(map[string]EntityRec)
	var rows *sql.Rows
	rows, err = mdq.db.Query("select id, entityid, hash from entity")
	if err != nil {
		return
	}
	defer rows.Close()
	for rows.Next() {
		var rec EntityRec
		if err = rows.Scan(&rec.id, &rec.entityid, &rec.hash); err != nil {
			return
		}
		entities[rec.entityid] = rec
	}
	if err = rows.Err(); err != nil { // no reason to actually check err, but if we later forget ...
		return
	}
	return
}

// Get - insecure Get if https is used, doesn't matter for metadata as we check the signature anyway
func get(url string) (body []byte, err error) {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{
		Transport: tr,
	}
	var resp *http.Response
	if resp, err = client.Get(url); err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	body, err = ioutil.ReadAll(resp.Body)
	return
}

