package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/alirezarajaee/callquality-ai/app/internal/api"
	"github.com/alirezarajaee/callquality-ai/app/internal/pipeline"
)

func main() {
	listen := flag.String(
		"listen",
		"127.0.0.1:8080",
		"HTTP listen address",
	)

	maxUploadMB := flag.Int64(
		"max-upload-mb",
		64,
		"maximum PCAP upload size in MiB",
	)

	flag.Parse()

	if *maxUploadMB <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --max-upload-mb must be greater than zero")
		os.Exit(2)
	}

	service, err := pipeline.NewService()
	if err != nil {
		log.Fatalf("initialize analysis service: %v", err)
	}

	handler, err := api.NewServer(
		service,
		api.Config{
			MaxUploadBytes: *maxUploadMB << 20,
		},
	)
	if err != nil {
		log.Fatalf("initialize HTTP API: %v", err)
	}

	server := &http.Server{
		Addr:              *listen,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}

	log.Printf("CallQuality AI API")
	log.Printf("Listening on http://%s", *listen)
	log.Printf("POST /api/v1/analyze")
	log.Printf("GET  /api/v1/health")
	log.Printf("GET  /api/v1/version")

	if err := server.ListenAndServe(); err != nil &&
		err != http.ErrServerClosed {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
