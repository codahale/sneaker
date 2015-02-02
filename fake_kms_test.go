package secman

import "github.com/awslabs/aws-sdk-go/gen/kms"

type FakeKMS struct {
	GenerateRequests  []kms.GenerateDataKeyRequest
	GenerateResponses []kms.GenerateDataKeyResponse
}

func (f *FakeKMS) GenerateDataKey(req *kms.GenerateDataKeyRequest) (*kms.GenerateDataKeyResponse, error) {
	f.GenerateRequests = append(f.GenerateRequests, *req)
	resp := f.GenerateResponses[0]
	f.GenerateResponses = f.GenerateResponses[1:]
	return &resp, nil
}
