package main

import (
	"fmt"
	"log"
	"os"
	"text/tabwriter"

	"net/url"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/kms"
	"github.com/awslabs/aws-sdk-go/gen/s3"
	"github.com/docopt/docopt-go"
	"github.com/stripe/secman"
)

const usage = `secman manages secrets.

Usage:
  secman ls [<pattern>]
  secman upload <file> <path>
  secman rm <path>
  secman pack <pattern> <file>
  secman unpack <file> <path>
  secman rotate [<pattern>]
  secman version

Options:
  -h --help  Show this help information.

Environment Variables:
  KMS_KEY_ID  The ID of the KMS key to use when encrypting secrets.
  S3_PATH     The S3 path where secrets will be stored (e.g. s3://bucket/path).
`

func main() {
	args, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		log.Fatal(err)
	}

	if args["version"] == true {
		fmt.Printf(
			"version: %s\ngoversion: %s\nbuildtime: %s\n",
			version, goVersion, buildTime,
		)
		return
	}

	manager := loadManager()

	if args["ls"] == true {
		// secman ls
		// secman ls *.txt,*.key

		var pattern string
		if s, ok := args["<pattern>"].(string); ok {
			pattern = s
		}

		files, err := manager.List(pattern)
		if err != nil {
			log.Fatal(err)
		}

		table := new(tabwriter.Writer)
		table.Init(os.Stdout, 2, 0, 2, ' ', 0)
		fmt.Fprintln(table, "key\tmodified\tsize\tetag")
		for _, f := range files {
			fmt.Fprintf(table, "%s\t%s\t%v\t%s\n",
				f.Path,
				f.LastModified.Format(conciseTime),
				f.Size,
				f.ETag,
			)
		}
		_ = table.Flush()

	} else if args["upload"] == true {
		file := args["<file>"].(string)
		path := args["<path>"].(string)

		// BUG(coda): implement upload

		fmt.Printf("upload %q %q\n", file, path)
	} else if args["rm"] == true {
		path := args["<path>"].(string)

		if err := manager.Rm(path); err != nil {
			log.Fatal(err)
		}
	} else if args["pack"] == true {
		pattern := args["<pattern>"].(string)
		file := args["<file>"].(string)

		// BUG(coda): implement pack

		fmt.Printf("pack %q %q\n", pattern, file)
	} else if args["unpack"] == true {
		file := args["<file>"].(string)
		path := args["<path>"].(string)

		// BUG(coda): implement unpack

		fmt.Printf("unpack %q %q\n", path, file)
	} else if args["rotate"] == true {
		var pattern string
		if s, ok := args["<pattern>"].(string); ok {
			pattern = s
		}

		// BUG(coda): implement rotate

		fmt.Printf("rotate %q\n", pattern)
	} else {
		fmt.Fprintf(os.Stderr, "Unknown command: %v\n", os.Args)
	}
}

func loadManager() *secman.Manager {
	region := os.Getenv("AWS_DEFAULT_REGION")
	if region == "" {
		region = "us-west-2"
		log.Printf("no region specified, defaulting to %s", region)
	}

	u, err := url.Parse(os.Getenv("S3_PATH"))
	if err != nil {
		log.Fatalf("bad S3_PATH: %s", err)
	}

	creds := aws.DetectCreds("", "", "")

	return &secman.Manager{
		Objects: s3.New(creds, region, nil),
		Keys:    kms.New(creds, region, nil),
		KeyID:   os.Getenv("KMS_KEY_ID"),
		Bucket:  u.Host,
		Prefix:  u.Path,
	}
}

var (
	version   = "unknown" // version of secman
	goVersion = "unknown" // version of go we build with
	buildTime = "unknown" // time of build
)

const (
	conciseTime = "2006-01-02T15:04"
)
