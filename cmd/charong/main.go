package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/piotrkowalczuk/ntypespqt"
	"github.com/piotrkowalczuk/pqt/pqtgo"
	"github.com/piotrkowalczuk/pqt/pqtsql"
	"github.com/piotrkowalczuk/qtypespqt"
)

var (
	schema, output string
	acronyms       = map[string]string{
		"id":   "ID",
		"http": "HTTP",
		"ip":   "IP",
		"net":  "NET",
		"irc":  "IRC",
		"io":   "IO",
		"uuid": "UUID",
		"db":   "DB",
	}
)

func init() {
	flag.StringVar(&schema, "schema", "charon", "")
	flag.StringVar(&output, "output", "schema.pqt", "")
}

func main() {
	file, err := openFile(output)
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	form := &pqtgo.Formatter{
		Acronyms:   acronyms,
		Visibility: pqtgo.Public,
	}
	sch := databaseSchema()
	genGo := &pqtgo.Generator{
		Formatter: form,
		Pkg:       "model",
		Version:   9.5,
		Plugins: []pqtgo.Plugin{
			&qtypespqt.Plugin{
				Formatter:  form,
				Visibility: pqtgo.Public,
			},
			&ntypespqt.Plugin{},
		},
	}
	genSQL := &pqtsql.Generator{}
	if err := genGo.GenerateTo(file, sch); err != nil {
		log.Fatal(err)
	}
	fmt.Fprint(file, "const SQL = `\n")
	if err := genSQL.GenerateTo(sch, file); err != nil {
		log.Fatal(err)
	}
	fmt.Fprint(file, "`")
}

func openFile(output string) (io.WriteCloser, error) {
	return os.OpenFile(output+".go", os.O_TRUNC|os.O_WRONLY|os.O_CREATE, 0660)
}
