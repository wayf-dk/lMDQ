module github.com/wayf-dk/lmdq

go 1.16

require (
	github.com/mattn/go-sqlite3 v1.14.8
	github.com/pkg/errors v0.9.1 // indirect
	github.com/stretchr/testify v1.7.0 // indirect
	github.com/wayf-dk/gosaml v0.0.0-20210625075105-0384b2997a7c
	github.com/wayf-dk/goxml v0.0.0-20210624110732-3d7665237fff
	gopkg.in/xmlpath.v1 v1.0.0-20140413065638-a146725ea6e7 // indirect
	x.config v0.0.0-00010101000000-000000000000
)

replace (
	github.com/wayf-dk/gosaml => ../gosaml
	github.com/wayf-dk/goxml => ../goxml
	x.config => ../hybrid-config
)
