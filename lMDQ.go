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
	"database/sql"
	"encoding/hex"
	_ "github.com/mattn/go-sqlite3"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"sort"
	"strings"
	"sync"
	"time"
)

type (
	EntityRec struct {
		id       int64
		entityid string
		hash     string
	}

	MDQ struct {
		db    *sql.DB
		stmt  *sql.Stmt
		Path  string
		Cache map[string]*MdXp
		Lock  sync.Mutex
		Table string
	}

	MdXp struct {
		*goxml.Xp
		created time.Time
	}
)

var (
	cacheduration = time.Minute * 1
)

func (xp *MdXp) Valid(duration time.Duration) bool {
	since := time.Since(xp.created)
	//log.Println(since, duration, since  < duration)
	return since < duration
}

func (mdq *MDQ) Open() (err error) {
	mdq.Cache = make(map[string]*MdXp)
	mdq.db, err = sql.Open("sqlite3", mdq.Path)
	if err != nil {
	    return
	}
	err = mdq.db.Ping()
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
		mdq.stmt, err = mdq.db.Prepare("select e.md md from entity_" + mdq.Table + " e, lookup_" + mdq.Table + " l where l.hash = ? and l.entity_id_fk = e.id")
		if err != nil {
			return
		}
	}

	k := key
	if strings.HasPrefix(key, "{sha1}") {
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
	err = mdq.stmt.QueryRow(key).Scan(&xml)
	switch {
	case err == sql.ErrNoRows:
		err = goxml.Wrap(err, "err:Metadata not found", "key:"+k, "table:"+mdq.Table)
		return
	case err != nil:
		return
	default:
		md := gosaml.Inflate(xml)
		xp = goxml.NewXp(md)
	}
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
	xp = goxml.NewXpFromString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" />`)

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

// getEntityList returns a map keyed by entityIDs for the
// current entities in the database
func (mdq *MDQ) getEntityList() (entities map[string]EntityRec, err error) {

	entities = make(map[string]EntityRec)
	var rows *sql.Rows
	rows, err = mdq.db.Query("select id, entityid, hash from entity_" + mdq.Table)
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
