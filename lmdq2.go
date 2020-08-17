// +build testmdq

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

package lmdq

import (
	"errors"
	"github.com/wayf-dk/goxml"
	"io/ioutil"
	"net/http"
	"net/url"
)

type (
	// MDQ refers to metadata query
	MDQ struct {
		Path              string
		Table, Rev, Short string
	}
)

var (
	MetaDataNotFoundError = errors.New("Metadata not found")
	paths                 = map[string]string{
		"hub": "http://localhost:9999/MDQ/hub/",
		"int": "http://localhost:9999/MDQ/int/",
		"idp": "http://localhost:9999/MDQ/idp/",
		"sp":  "http://localhost:9999/MDQ/sp/",
	}
)

// Open refers to open metadata file
func (mdq *MDQ) Open() (err error) {
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

// WebMDQ - Export of dbget
func (mdq *MDQ) WebMDQ(key string) (xp *goxml.Xp, xml []byte, err error) {
	return mdq.dbget(key, true)
}

func (mdq *MDQ) dbget(key string, cache bool) (xp *goxml.Xp, xml []byte, err error) {
	client := &http.Client{}
	q := paths[mdq.Short] + url.PathEscape(key)
	req, _ := http.NewRequest("GET", q, nil)
	response, err := client.Do(req)

	if err != nil || response.StatusCode == 500 {
		err = goxml.Wrap(MetaDataNotFoundError, "err:Metadata not found", "key:"+key, "table:"+mdq.Short)
		return nil, nil, err
	}

	defer response.Body.Close()
	xml, err = ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, nil, err
	}
	//md := gosaml.Inflate(xml)
	xp = goxml.NewXp(xml)
	return xp, xml, err
}
