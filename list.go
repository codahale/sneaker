package sneaker

import (
	"path"
	"strings"
	"time"

	"github.com/awslabs/aws-sdk-go/aws"
	"github.com/awslabs/aws-sdk-go/gen/s3"
)

// List returns a list of files which match the given pattern, or if the pattern
// is blank, all files.
func (m *Manager) List(pattern string) ([]File, error) {
	resp, err := m.Objects.ListObjects(&s3.ListObjectsRequest{
		Bucket: aws.String(m.Bucket),
		Prefix: aws.String(m.Prefix),
	})
	if err != nil {
		return nil, err
	}

	var secrets []File
	for _, obj := range resp.Contents {
		if strings.HasSuffix(*obj.Key, aesExt) {
			secrets = append(secrets, File{
				Path:         (*obj.Key)[len(m.Prefix) : len(*obj.Key)-len(aesExt)],
				LastModified: obj.LastModified.In(time.UTC),
				Size:         int(*obj.Size),
				ETag:         strings.Replace(*obj.ETag, "\"", "", -1),
			})
		}
	}

	if pattern == "" {
		return secrets, nil
	}

	var matchedSecrets []File
	for _, f := range secrets {
		ok, err := matchPath(pattern, f.Path)
		if err != nil {
			return nil, err
		}

		if ok {
			matchedSecrets = append(matchedSecrets, f)
		}
	}
	return matchedSecrets, nil
}

func matchPath(pattern, name string) (bool, error) {
	for _, s := range strings.Split(pattern, ",") {
		m, err := path.Match(s, name)
		if err != nil {
			return false, err
		}

		if m {
			return true, nil
		}
	}
	return false, nil
}
