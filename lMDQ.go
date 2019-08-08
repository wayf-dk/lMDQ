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
	"crypto/sha1"
	"database/sql"
	"encoding/hex"
	"errors"
	// 	_ "github.com/mattn/go-sqlite3" for handling sqlite3
	_ "github.com/mattn/go-sqlite3"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type (
	// EntityRec refers entity info
	EntityRec struct {
		id       int64
		entityid string
		hash     string
	}
	// MDQ refers to metadata query
	MDQ struct {
		db                *sql.DB
		stmt              *sql.Stmt
		Path              string
		Cache             map[string]*MdXp
		Lock              sync.RWMutex
		Table, Rev, Short string
	}
	// MdXp refers to check validity
	MdXp struct {
		*goxml.Xp
		xml     []byte
		created time.Time
	}
)

var (
	cacheduration = time.Minute * 60
	// MetaDataNotFoundError refers to error
	MetaDataNotFoundError = errors.New("Metadata not found")
	hexChars              = regexp.MustCompile("^[a-fA-F0-9]+$")
)

// Valid refers to check the validity of metadata
func (xp *MdXp) Valid(duration time.Duration) bool {
	since := time.Since(xp.created)
	//log.Println(since, duration, since  < duration)
	return since < duration
}

// Open refers to open metadata file
func (mdq *MDQ) Open() (err error) {
	mdq.Lock.Lock()
	defer mdq.Lock.Unlock()
	mdq.Cache = make(map[string]*MdXp)
	if mdq.db != nil {
		mdq.db.Close()
	}
	mdq.db, err = sql.Open("sqlite3", mdq.Path)
	if err != nil {
		return
	}
	mdq.stmt, err = mdq.db.Prepare("select e.md md from entity_" + mdq.Table + " e, lookup_" + mdq.Table + " l where ? < l.hash||'z' and l.hash||'z' <= ? and l.entity_id_fk = e.id")
	// This is supposed to be a very smart wayf do to prefix search - keep an eye on whether a 10 char prefix ie. using 40 bits is enough
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
	xp, _, err = mdq.dbget(key, true)
	return
}

func (mdq *MDQ) WebMDQ(key string) (xp *goxml.Xp, xml []byte, err error) {
	return mdq.dbget(key, true)
}

func (mdq *MDQ) dbget(key string, cache bool) (xp *goxml.Xp, xml []byte, err error) {
	k := key
	if strings.HasPrefix(key, "{sha1}") {
		key = key[6:]
	} else if hexChars.MatchString(key) {

	} else {
		hash := sha1.Sum([]byte(key))
		key = hex.EncodeToString(append(hash[:]))
	}
	key = key[:10] // only use the first 10 chars for key
	mdq.Lock.RLock()
	cachedxp := mdq.Cache[key]
	if cachedxp != nil && cachedxp.Valid(cacheduration) {
		xp = cachedxp.Xp.CpXp()
		xml = cachedxp.xml
		mdq.Lock.RUnlock()
		return
	}
	mdq.Lock.RUnlock()

	err = mdq.stmt.QueryRow(key, key+"z").Scan(&xml)
	switch {
	case err == sql.ErrNoRows:
		err = goxml.Wrap(MetaDataNotFoundError, "err:Metadata not found", "key:"+k, "table:"+mdq.Table)
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
		mdxp.xml = xml
		mdxp.created = time.Now()
		mdq.Lock.Lock()
		mdq.Cache[key] = mdxp
		mdq.Lock.Unlock()
	}
	return
}

// MDQFilter refers Filtering by xpath for testing purposes
func (mdq *MDQ) MDQFilter(xpathfilter string) (xp *goxml.Xp, numberOfEntities int, err error) {
	recs, err := mdq.getEntityList()
	if err != nil {
		return
	}

	// get the entities into an ordered slice
	index := make([]string, len(recs))
	i := 0
	for k := range recs {
		index[i] = k
		i++
	}
	sort.Strings(index)

	//log.Println(xpathfilter)
	xp = goxml.NewXpFromString(`<md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" />`)

	root, _ := xp.Doc.DocumentElement()
	for _, entityID := range index {
		ent, _, _ := mdq.dbget(entityID, false)

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
