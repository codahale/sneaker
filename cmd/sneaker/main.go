// sneaker is a command-line tool for securely managing secrets using Amazon Web
// Service's Key Management Service and S3.
package main

import (
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/kms"
	"github.com/awslabs/aws-sdk-go/gen/s3"
	"github.com/docopt/docopt-go"
	"github.com/stripe/sneaker"
)

const usage = `sneaker manages secrets.

Usage:
  sneaker ls [<pattern>]
  sneaker upload <file> <path>
  sneaker rm <path>
  sneaker pack <pattern> <file> [--context=<context>]
  sneaker unpack <file> <path> [--context=<context>]
  sneaker rotate [<pattern>]
  sneaker version

Options:
  -h --help  Show this help information.

Environment Variables:
  SNEAKER_REGION   The AWS region where the key and bucket are located.
  SNEAKER_KEY_ID   The KMS key to use when encrypting secrets.
  SNEAKER_S3_PATH  Where secrets will be stored (e.g. s3://bucket/path).
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
		// sneaker ls
		// sneaker ls *.txt,*.key

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

		f, err := os.Open(file)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()

		if err := manager.Upload(path, f); err != nil {
			log.Fatal(err)
		}
	} else if args["rm"] == true {
		path := args["<path>"].(string)

		if err := manager.Rm(path); err != nil {
			log.Fatal(err)
		}
	} else if args["pack"] == true {
		pattern := args["<pattern>"].(string)
		file := args["<file>"].(string)
		var context map[string]string
		if s, ok := args["--context"].(string); ok {
			c, err := parseContext(s)
			if err != nil {
				log.Fatal(err)
			}
			context = c
		}

		// list files
		files, err := manager.List(pattern)
		if err != nil {
			log.Fatal(err)
		}

		paths := make([]string, 0, len(files))
		for _, f := range files {
			paths = append(paths, f.Path)
		}

		// download secrets
		secrets, err := manager.Download(paths)
		if err != nil {
			log.Fatal(err)
		}

		var w io.Writer
		if file == "-" {
			// write to STDOUT if file is -
			w = os.Stdout
		} else {
			f, err := os.Create(file)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			w = f
		}

		// pack secrets
		if err := manager.Pack(secrets, context, w); err != nil {
			log.Fatal(err)
		}
	} else if args["unpack"] == true {
		file := args["<file>"].(string)
		path := args["<path>"].(string)
		var context map[string]string
		if s, ok := args["--context"].(string); ok {
			c, err := parseContext(s)
			if err != nil {
				log.Fatal(err)
			}
			context = c
		}

		var r io.Reader
		if file == "-" {
			// read from STDIN if file is -
			r = os.Stdin
		} else {
			f, err := os.Open(file)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			r = f
		}

		var w io.Writer
		if path == "-" {
			// write to STDOUT if path is -
			w = os.Stdout
		} else {
			f, err := os.Create(path)
			if err != nil {
				log.Fatal(err)
			}
			defer f.Close()
			w = f
		}

		r, err := manager.Unpack(context, r)
		if err != nil {
			log.Fatal(err)
		}

		if _, err := io.Copy(w, r); err != nil {
			log.Fatal(err)
		}
	} else if args["rotate"] == true {
		var pattern string
		if s, ok := args["<pattern>"].(string); ok {
			pattern = s
		}

		if err := manager.Rotate(pattern, func(s string) {
			log.Printf("rotating %s", s)
		}); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Unknown command: %v\n", os.Args)
	}
}

func loadManager() *sneaker.Manager {
	region := os.Getenv("SNEAKER_REGION")
	if region == "" {
		log.Fatal("missing SNEAKER_REGION")
	}

	u, err := url.Parse(os.Getenv("SNEAKER_S3_PATH"))
	if err != nil {
		log.Fatalf("bad SNEAKER_S3_PATH: %s", err)
	}

	creds := aws.DetectCreds("", "", "")

	return &sneaker.Manager{
		Objects: s3.New(creds, region, nil),
		Keys:    kms.New(creds, region, nil),
		KeyID:   os.Getenv("SNEAKER_KEY_ID"),
		Bucket:  u.Host,
		Prefix:  u.Path,
	}
}

func parseContext(s string) (map[string]string, error) {
	if s == "" {
		return nil, nil
	}

	context := map[string]string{}
	for _, v := range strings.Split(s, ",") {
		parts := strings.SplitN(v, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("unable to parse context: %q", v)
		}
		context[parts[0]] = parts[1]
	}
	return context, nil
}

var (
	version   = "unknown" // version of sneaker
	goVersion = "unknown" // version of go we build with
	buildTime = "unknown" // time of build
)

const (
	conciseTime = "2006-01-02T15:04"
)
