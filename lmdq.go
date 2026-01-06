package lmdq

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

import (
    "bytes"
	"crypto/sha1"
	"database/sql"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"sync"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/wayf-dk/gosaml"
	"github.com/wayf-dk/goxml"
	"x.config"
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
		config.MdDb
		db    *sql.DB
		onestmt, multistmt, selfstmt  *sql.Stmt
		Cache map[string]*MdXp
		Lock  sync.RWMutex
	}
	// MdXp refers to check validity
	MdXp struct {
		*goxml.Xp
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
	if mdq.Mdq != "" {
		return
	}
	mdq.Cache = make(map[string]*MdXp)
	if mdq.db != nil {
		mdq.db.Close()
	}
	mdq.db, err = sql.Open("sqlite3", mdq.Dsn)
	if err != nil {
		return
	}

    findEntity := ` ? < l.hash||'z' AND l.hash||'z' <= ?||'z' `

	mdq.multistmt, err = mdq.db.Prepare(`SELECT
    e.md
FROM
    entity_` + mdq.Table + ` e
WHERE
    e.id IN
    (   SELECT
            entity_id_fk
        FROM
            fed_` + mdq.Table + ` f
        WHERE
            f.fed IN
            (   SELECT
                    f.fed
                FROM
                    fed_` + mdq.TableRev + `    f,
                    lookup_` + mdq.TableRev + ` l
                WHERE ` + findEntity + `AND l.entity_id_fk = f.entity_id_fk ))`)

    mdq.onestmt, err = mdq.db.Prepare(`SELECT
    e.md
FROM
    (   SELECT
            e.md
        FROM
            entity_` + mdq.Table + ` e,
            lookup_` + mdq.Table + ` l
        WHERE
           ` + findEntity + `
            AND l.entity_id_fk = e.id) e,
    (   SELECT
            f.fed
        FROM
            lookup_` + mdq.Table + ` l,
            fed_` + mdq.Table + `    f
        WHERE
            ` + findEntity + `
            AND l.entity_id_fk = f.entity_id_fk

        INTERSECT

        SELECT
            f.fed
        FROM
            lookup_` + mdq.TableRev + ` l,
            fed_` + mdq.TableRev + `    f
        WHERE
            ` + findEntity + `
            AND l.entity_id_fk = f.entity_id_fk ) i limit 1;
`)
	mdq.selfstmt, err = mdq.db.Prepare(`select e.md md from entity_` + mdq.Table + ` e where e.id in (SELECT l.entity_id_fk FROM lookup_` + mdq.Table + ` l WHERE` + findEntity + `) limit 1`)
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
	if mdq.Mdq == "" {
	    return mdq.WebMDQ(key, key)
//		return mdq.dbget(key, true)
	} else {
		return mdq.mdqget(key, true)
	}
}

func c14n(key string) (string) {
    if hexChars.MatchString(key) || key == "" {
        // already sha1'ed - do nothing
	} else {
	    key = fmt.Sprintf("%x", sha1.Sum([]byte(key)))
	}
    return key
}

func (mdq *MDQ) WebMDQ(key, key2 string) (xp *goxml.Xp, err error) {
    var rows *sql.Rows
    key, key2 = c14n(key), c14n(key2)
    if key == key2 {
      	rows, err = mdq.selfstmt.Query(key, key)
    } else if key2 != "" {
        rows, err = mdq.onestmt.Query(key2, key2, key2, key2, key, key)
    } else {
    	rows, err = mdq.multistmt.Query(key, key)
    }
	if err != nil {
		return
	}
	defer rows.Close()
	md, c := []byte{}, 0
	for rows.Next() {
		var buf []byte
		if err = rows.Scan(&buf); err != nil {
			return
		}
		prefix := `<?xml version="1.0" encoding="UTF-8"?>
`
		entitymd, _ := bytes.CutPrefix(gosaml.Inflate(buf), []byte(prefix))
		md = append(md, entitymd...)
		c++
	}
	if c == 0 {
	    return xp, MetaDataNotFoundError
	}
	if c >= 2 {
        md = append([]byte(`<?xml version="1.0" encoding="UTF-8"?><md:EntitiesDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata">`), md...)
        md = append(md, `</md:EntitiesDescriptor>`...)
    }
	xp = goxml.NewXp(md)
    if c == 1 {
    	testify(xp)
    }
    for _, signature := range xp.Query(nil, "./md:EntityDescriptor/ds:Signature") {
        xp.Rm(signature, ".")
    }
	return
}

func (mdq *MDQ) dbget(key string, cache bool) (xp *goxml.Xp, err error) {
    k := key
    key = c14n(key)
	mdq.Lock.RLock()
	cachedxp := mdq.Cache[key]
	if cachedxp != nil && cachedxp.Valid(cacheduration) {
		xp = cachedxp.Xp.CpXp()
		mdq.Lock.RUnlock()
		return
	}
	mdq.Lock.RUnlock()
    var xml []byte
	err = mdq.selfstmt.QueryRow(key, key).Scan(&xml)
	switch {
	case err == sql.ErrNoRows:
		err = goxml.Wrap(MetaDataNotFoundError, "err:Metadata not found", "key:"+k, "table:"+mdq.Short)
		return
	case err != nil:
		return
	default:
		md := gosaml.Inflate(xml)
		xp = goxml.NewXp(md)
		testify(xp)
	}
	if cache {
		mdxp := new(MdXp)
		mdxp.Xp = xp
		mdxp.created = time.Now()
		mdq.Lock.Lock()
		mdq.Cache[key] = mdxp
		mdq.Lock.Unlock()
	}
	return
}

func (mdq *MDQ) mdqget(key string, cache bool) (xp *goxml.Xp, err error) {
	client := &http.Client{}
	q := mdq.Mdq + url.PathEscape(key)
	req, _ := http.NewRequest("GET", q, nil)
	response, err := client.Do(req)

	if err != nil || response.StatusCode == 500 {
		err = goxml.Wrap(MetaDataNotFoundError, "err:Metadata not found", "key:"+key, "table:"+mdq.Short)
		return nil, err
	}

	defer response.Body.Close()
	xml, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	//md := gosaml.Inflate(xml)
	xp = goxml.NewXp(xml)
	return xp, err
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

/**
	Testify adds the config.Testcertificate(1|2) in front of the existing certificate in the metadata for specific entities
	It has to be added in front of because the 1st certificate is used for doing the signing
	The existing certificate has to be kept because if jwt2SAML is used by the IdP the assertion is signed by the hub itself,
	even when testing the IdP might use the prod hybrid
*/
func testify(xp *goxml.Xp) {
	if config.MetadataMods {
	    for _, cert := range config.TestCerts {
            entityID := xp.Query1(nil, "/md:EntityDescriptor/@entityID")
            sso := xp.Query1(nil, "//md:SingleSignOnService/@Location")
            insertCert(xp, entityID, sso, cert)
		}
	}
}

func insertCert(xp *goxml.Xp, entityID, sso, cert string) {
	if before := xp.Query(nil, "./md:IDPSSODescriptor/md:KeyDescriptor"); len(before) > 0 {
		xp.QueryDashP(nil, "/md:IDPSSODescriptor/md:KeyDescriptor[0]/ds:KeyInfo/ds:X509Data/ds:X509Certificate", cert, before[0])
	}
	if before := xp.Query(nil, "./md:SPSSODescriptor/md:KeyDescriptor"); len(before) > 0 {
		xp.QueryDashP(nil, "/md:SPSSODescriptor/md:KeyDescriptor[0]/ds:KeyInfo/ds:X509Data/ds:X509Certificate", cert, before[0])
	}
}
