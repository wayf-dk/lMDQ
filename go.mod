module github.com/wayf-dk/lmdq

go 1.22.0

require (
	github.com/mattn/go-sqlite3 v1.14.16
	github.com/wayf-dk/gosaml v0.0.0-20231209191011-848a65396bfa
	github.com/wayf-dk/goxml v0.0.0-20230926122057-d976ff55f917
	x.config v0.0.0-00010101000000-000000000000
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/wayf-dk/go-libxml2 v0.0.0-20231207144727-d602dab8cded // indirect
	github.com/wayf-dk/goeleven v0.0.0-20230816115740-d287bc08e939 // indirect
	golang.org/x/crypto v0.19.0 // indirect
	golang.org/x/sys v0.17.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/wayf-dk/gosaml => ../gosaml
	github.com/wayf-dk/goxml => ../goxml
	x.config => ../hybrid-config
)
