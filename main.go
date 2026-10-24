package main

import (
	"context"
	"flag"
	"log"

	"github.com/VincentSchmid/terraform-provider-zyxel/internal/provider"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
)

var version = "dev"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "Run provider in debug mode")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/VincentSchmid/zyxel",
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
