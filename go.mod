module github.com/wayf-dk/lmdq

go 1.22

require (
	github.com/mattn/go-sqlite3 v1.14.16
	github.com/wayf-dk/gosaml v0.0.0-20231209191011-848a65396bfa
	github.com/wayf-dk/goxml v0.0.0-20230926122057-d976ff55f917
	x.config v0.0.0-00010101000000-000000000000
)

require (
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/wayf-dk/go-libxml2 v0.0.0-20210308214358-9c9e7b3a8e9c // indirect
	github.com/wayf-dk/goeleven v0.0.0-20210622080738-31052701ada3 // indirect
	golang.org/x/crypto v0.0.0-20210322153248-0c34fe9e7dc2 // indirect
	golang.org/x/sys v0.0.0-20201119102817-f84b799fce68 // indirect
	gopkg.in/xmlpath.v1 v1.0.0-20140413065638-a146725ea6e7 // indirect
)

replace (
	github.com/wayf-dk/gosaml => ../gosaml
	github.com/wayf-dk/goxml => ../goxml
	x.config => ../hybrid-config
)
