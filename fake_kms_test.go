package sneaker

import "github.com/awslabs/aws-sdk-go/gen/kms"

type FakeKMS struct {
	GenerateRequests  []kms.GenerateDataKeyRequest
	GenerateResponses []kms.GenerateDataKeyResponse

	DecryptRequests  []kms.DecryptRequest
	DecryptResponses []kms.DecryptResponse
}

func (f *FakeKMS) GenerateDataKey(req *kms.GenerateDataKeyRequest) (*kms.GenerateDataKeyResponse, error) {
	f.GenerateRequests = append(f.GenerateRequests, *req)
	resp := f.GenerateResponses[0]
	f.GenerateResponses = f.GenerateResponses[1:]
	return &resp, nil
}

func (f *FakeKMS) Decrypt(req *kms.DecryptRequest) (*kms.DecryptResponse, error) {
	f.DecryptRequests = append(f.DecryptRequests, *req)
	resp := f.DecryptResponses[0]
	f.DecryptResponses = f.DecryptResponses[1:]
	return &resp, nil
}
