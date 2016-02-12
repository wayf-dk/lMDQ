/*  lMDQ is a MDQ server that caches metadata locally so it's local clients can lookup
    pre-checked metadata and not depend on a working connection to a remote MDQ server.

    It uses SQLite as it's datastore and allows lookup by either entityID or Location.
    The latter is used by WAYF for it's mass hosting services BIRK and KRIB.

    It can also be used as a library for just looking up metadata inside a go program.

    Or a client can use the SQLite database directly using the following query:

		"select e.md, e.hash from entity e, lookup l where l.hash = $1 and l.entity_id_fk = e.id and e.validuntil >= $2"

    where $1 is the lowercase hex sha1 of the entityID or location without the {sha1} prefix
    $2 is the feed and $3 is the current epoch.

    to-do:
        - caching interface
*/

package lMDQ

import (
	"crypto"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	_ "github.com/mattn/go-sqlite3"
	"github.com/wayf-dk/gosaml"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	metadataSchema = "/home/mz/src/github.com/wayf-dk/gosaml/schemas/saml-schema-metadata-2.0.xsd"
	// pragma wal ???
	lMDQSchema = `
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS entity
(
    id INTEGER PRIMARY KEY,
    entityid text not null,
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
		db        *sql.DB
		stmt      *sql.Stmt
		url, hash string
	}
)

var (
    mdcache map[string]*gosaml.Xp
    mdlock sync.Mutex
    cacheduration = time.Minute * 1
)

func init() {
    mdcache = make(map[string]*gosaml.Xp)
}

func (mdq *MDQ) Open(path string) (mdq1 *MDQ, err error) {
	mdq.db, err = sql.Open("sqlite3", path)
	if err != nil {
		return
	}
	_, err = mdq.db.Exec(lMDQSchema)
	if err != nil {
	    log.Println(err)
		return
	}
	mdq.stmt, err = mdq.db.Prepare(`select e.md, e.hash from entity e, lookup l, validuntil v
	where l.hash = $1 and l.entity_id_fk = e.id and v.validuntil >= $2`)
	if err != nil {
		return
	}
	mdq1 = mdq
	return
}

// MDQ looks up an entity using the supplied feed and key.
// The key can be an entityID or a location, optionally in {sha1} format
// It returns a non nil err if the entity is not found
// and the metadata and a hash/etag over the content if it is.
// The hash can be used to decide if a cached dom object is still valid,
// This might be an optimization as the database lookup is much faster that the parsing.

func (mdq *MDQ) MDQ(key string) (xp *gosaml.Xp, hash string, err error) {
	const prefix = "{sha1}"
	if strings.HasPrefix(key, prefix) {
		key = key[6:]
	} else {
		key = hex.EncodeToString(gosaml.Hash(crypto.SHA1, key))
	}

    mdlock.Lock()
    defer mdlock.Unlock()
    cachedxp := mdcache[key]
    if cachedxp != nil && cachedxp.Valid(cacheduration) {
        xp = cachedxp.CpXp()
        return
    }

	var xml []byte
	err = mdq.stmt.QueryRow(key, time.Now().Unix()).Scan(&xml, &hash)

	xp = gosaml.NewXp(xml)
	mdcache[key] = xp
	//	const ssoquery = "./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location"
	//	_ = xp.Query1(nil, ssoquery)
	return
}

func (mdq *MDQ) Update() (err error) {
	start := time.Now()
	log.Println("lMDQ updating", mdq.url)

	recs, err := mdq.getEntityList()
	if err != nil {
		return err
	}

	dom, err := MDQclient(mdq.url, "")
	//	ents := dom.Query(nil, "./md:EntityDescriptor")
	//	dom.UnlinkNode(ents[25])
	//    ents[26].SetAttr("anton", "banton")

	if _, err := dom.SchemaValidate(metadataSchema); err != nil {
		log.Println("feed", "SchemaError")
	}

	certificate := dom.Query(nil, "/md:EntitiesDescriptor/ds:Signature/ds:KeyInfo/ds:X509Data/ds:X509Certificate")
	if len(certificate) != 1 {
		err = errors.New("Metadata not signed")
		return
	}
	keyname, key, err := gosaml.PublicKeyInfo(dom.NodeGetContent(certificate[0]))

	if err != nil {
		return
	}

	ok := dom.VerifySignature(nil, key)
	if !ok || keyname != mdq.hash {
		return fmt.Errorf("Signature check failed. Signature %t, %s = %s", ok, keyname, mdq.hash)
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

	lookupInsertStmt, err := tx.Prepare("insert into lookup (hash, entity_id_fk) values (?, ?)")
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
	entities := dom.Query(nil, "./md:EntityDescriptor")
	for _, entity := range entities {
		entityID := dom.Query1(entity, "@entityID")
		md := gosaml.NewXpFromNode(entity).X2s()
		rec := recs[entityID]
		id := rec.id
		hash := hex.EncodeToString(gosaml.Hash(crypto.SHA1, md))
		oldhash := rec.hash
		if rec.hash == hash { // no changes
			delete(recs, entityID) // remove so it won't be deleted
			nochange++
			continue
		} else if oldhash != "" { // update is delete + insert - then the cacading delete will also delete the potential stale lookup entries
			_, err = entityDeleteStmt.Exec(rec.id)
			if err != nil {
				return
			}
			updated++
			log.Printf("lMDQ updated entityID: %s", entityID)
			delete(recs, entityID) // updated - remove so it won't be deleted
		} else {
			new++
			log.Printf("lMDQ new entityID: %s", entityID)
		}
		var res sql.Result
		res, err = entityInsertStmt.Exec(entityID, md, hash)
		if err != nil {
			return err
		}

		id, _ = res.LastInsertId()

		_, err = lookupInsertStmt.Exec(hex.EncodeToString(gosaml.Hash(crypto.SHA1, entityID)), id)
		if err != nil {
			return
		}
		locations := dom.Query(entity, "./md:IDPSSODescriptor/md:SingleSignOnService[@Binding='urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect']/@Location")
		for _, location := range locations {
			//log.Println(i, dom.NodeGetContent(location))
			_, err = lookupInsertStmt.Exec(hex.EncodeToString(gosaml.Hash(crypto.SHA1, dom.NodeGetContent(location))), id)
			if err != nil {
				return
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


	log.Printf("lMDQ finished new: %d updated: %d nochange: %d deleted: %d validUntil: %s duration: %.1f",
		new, updated, nochange, deleted, time.Unix(validUntil, 0).Format(time.RFC3339), time.Since(start).Seconds())
	return
}

// getEntityList returns a map keyed by entityIDs for the
// current entities in the database belonging to the feed
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

// MDQclient - read some metadata from either a MDQ Server or a normal feed url.
// Key is either en entityID or Location - allows lookup entity by endpoints,
// this is currently only supported by the phph.wayf.dk/MDQ and is used by WAYF for mass virtual entity hosting
// in BIRK and KRIB. THE PHPh MDQ server only understands the sha1 encoded parameter and currently only
// understands request for 1 entity at a time.
// If key is "" the mdq string is used as a normal feed url.
func MDQclient(mdq, key string) (mdxp *gosaml.Xp, err error) {
	if key != "" {
		mdq = mdq + "/entities/{sha1}" + hex.EncodeToString(gosaml.Hash(crypto.SHA1, key))
	}
	url, _ := url.Parse(mdq)

	tr := &http.Transport{
		TLSClientConfig:    &tls.Config{InsecureSkipVerify: true},
		Dial:               func(network, addr string) (net.Conn, error) { return net.Dial("tcp", addr) },
		DisableCompression: true,
	}
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return errors.New("redirect not supported") },
	}

	var req *http.Request
	if req, err = http.NewRequest("GET", url.String(), nil); err != nil {
		return
	}
	var resp *http.Response
	if resp, err = client.Do(req); err != nil {
		return
	}
	if resp.StatusCode != 200 {
		if key == "" {
			key = mdq
		}
		err = fmt.Errorf("Metadata not found for entity: %s", key)
		//	    err = fmt.Errorf("looking for: '%s' using: '%s' MDQ said: %s\n", key, url.String(), resp.Status)
		return
	}
	var md []byte
	if md, err = ioutil.ReadAll(resp.Body); err != nil {
		return
	}

	mdxp = gosaml.NewXp(md)
	return
}
