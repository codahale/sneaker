package secman

import "github.com/awslabs/aws-sdk-go/gen/s3"

type FakeS3 struct {
	ListRequests  []s3.ListObjectsRequest
	ListResponses []s3.ListObjectsOutput
}

func (f *FakeS3) ListObjects(req *s3.ListObjectsRequest) (*s3.ListObjectsOutput, error) {
	f.ListRequests = append(f.ListRequests, *req)
	resp := f.ListResponses[0]
	f.ListResponses = f.ListResponses[1:]
	return &resp, nil
}
