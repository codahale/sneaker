package main

import (
	"fmt"
	"os"

	"github.com/docopt/docopt-go"
)

const usage = `kms-secrets manages secrets.

Usage:
  kms-secrets ls [<pattern>]
  kms-secrets upload <file> <path>
  kms-secrets rm <path>
  kms-secrets pack <pattern> <file>
  kms-secrets unpack <file> <path>
  kms-secrets rotate [<pattern>]
  kms-secrets version

Options:
  -h --help  Show this help information.

Environment Variables:
  KMS_KEY_ID  The ID of the KMS key to use when encrypting secrets.
  S3_PATH     The S3 path where secrets will be stored (e.g. s3://bucket/path).
`

func main() {
	args, err := docopt.Parse(usage, nil, true, version, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(-1)
	}

	if args["version"] == true {
		fmt.Printf(
			"version: %s\ngoversion: %s\nbuildtime: %s\n",
			version, goVersion, buildTime,
		)
		return
	}

	if args["ls"] == true {
		var pattern string
		if s, ok := args["<pattern>"].(string); ok {
			pattern = s
		}

		fmt.Printf("ls %q\n", pattern)
	} else if args["upload"] == true {
		file := args["<file>"].(string)
		path := args["<path>"].(string)

		fmt.Printf("upload %q %q\n", file, path)
	} else if args["rm"] == true {
		path := args["<path>"].(string)

		fmt.Printf("rm %q\n", path)
	} else if args["pack"] == true {
		pattern := args["<pattern>"].(string)
		file := args["<file>"].(string)

		fmt.Printf("pack %q %q\n", pattern, file)
	} else if args["unpack"] == true {
		file := args["<file>"].(string)
		path := args["<path>"].(string)

		fmt.Printf("unpack %q %q\n", path, file)
	} else if args["rotate"] == true {
		var pattern string
		if s, ok := args["<pattern>"].(string); ok {
			pattern = s
		}

		fmt.Printf("rotate %q\n", pattern)
	} else {
		fmt.Fprintf(os.Stderr, "Unknown command: %v\n", os.Args)
	}
}

var (
	version   = "unknown" // version of kms-secrets
	goVersion = "unknown" // version of go we build with
	buildTime = "unknown" // time of build
)
