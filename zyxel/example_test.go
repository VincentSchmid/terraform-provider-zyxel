package zyxel_test

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/VincentSchmid/terraform-provider-zyxel/zyxel"
)

func ExampleClient_ReadNATRule() {
	client, err := zyxel.NewClient("http://192.0.2.1", zyxel.Credentials{
		Username: os.Getenv("ZYXEL_USER"),
		Password: os.Getenv("ZYXEL_PASS"),
	}, 10*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	rule, err := client.ReadNATRule(context.Background(), "web")
	if err != nil {
		log.Fatal(err)
	}
	if rule != nil {
		fmt.Println(rule.InternalClient)
	}
}
