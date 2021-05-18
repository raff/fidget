package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
)

const (
	confDefault = "fidget.hcl"
	certFile    = "fidget.pem"
)

func main() {
	config := Config{Port: ":8080"}

	flag.StringVar(&config.Port, "port", ":8080", "proxy listenting port")
	flag.BoolVar(&config.Verbose, "verbose", false, "proxy verbose")
	flag.BoolVar(&config.Mitm, "mitm", false, "man in the middle")
	flag.BoolVar(&config.Logs, "Logs", false, "log requests/responses")

	conf := flag.String("conf", "", fmt.Sprintf("configuration file (default: %v)", confDefault))
	export := flag.Bool("export", false, "export CA (fidget.pem)")
	flag.Parse()

	if *export {
		writeCA(certFile)
		return
	}

	if *conf == "" {
		_, err := os.Stat(confDefault)
		if os.IsNotExist(err) {
			log.Println("No default configuration file found:", confDefault)
			log.Println("Continue without...")
		} else if err == nil {
			*conf = confDefault
		} else {
			log.Fatal(err)
		}
	}

	if *conf != "" {
		if err := config.Load(*conf); err != nil {
			log.Fatal(err)
		}
	}

	setCA()

	proxy, _ := config.NewProxy()

	log.Println("Listening on", config.Port)
	log.Fatal(http.ListenAndServe(config.Port, proxy))
}
