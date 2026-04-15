// Command faramesh-registry is a minimal local registry compatible with
// faramesh hub pack search and install (GET /v1/search, GET /v1/packs/...).
package main

import (
	"flag"
	"log"
	"net/http"

	"github.com/faramesh/faramesh-core/internal/hub/refsrv"
)

func main() {
	catalogPath := flag.String("catalog", "", "path to catalog.json (optional; default serves a built-in demo pack)")
	listen := flag.String("listen", "127.0.0.1:9876", "listen address")
	flag.Parse()

	cat, err := refsrv.LoadCatalogFromFile(*catalogPath)
	if err != nil {
		log.Fatalf("catalog: %v", err)
	}
	log.Printf("faramesh reference registry at http://%s", *listen)
	log.Fatal(http.ListenAndServe(*listen, refsrv.NewHandler(cat)))
}
