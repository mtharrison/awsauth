package v4

import (
	"encoding/hex"
	"testing"
)

func assertStringsEqual(actual, expected string, t *testing.T) {
	if actual != expected {
		t.Error("The actual result did not match the expected result", actual)
	}
}

func TestGetHeaders(t *testing.T) {
	options := RequestOptions{
		payload:         []byte("My Payload"),
		destinationPath: "my/upload/path",
		bucketName:      "my-bucket",
		region:          "my-region",
		secretAccessKey: "my-key",
		accessKeyID:     "my-key-id",
	}

	headers := GetHeaders(options)

	assertStringsEqual(headers["Host"], "my-bucket.s3.amazonaws.com", t)
	assertStringsEqual(headers["x-amz-content-sha256"], "9f14c6e5190a42e25f59c71cffea24741a273e80820760f5a9802a4e4c2a0300", t)
	assertStringsEqual(headers["x-amz-date"], getAmazonDate(), t)
}

func TestGetAuthorizationHeader(t *testing.T) {
	options := RequestOptions{
		accessKeyID: "my-key",
		region:      "my-region",
	}

	signedReq := signedRequest{
		date:      "20060102T150405Z",
		signature: "signature",
	}

	actualResult := getAuthorizationHeader(options, signedReq)
	expectedResult := "AWS4-HMAC-SHA256 Credential=my-key/20060102T150405Z/my-region/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=signature"

	assertStringsEqual(actualResult, expectedResult, t)
}

func TestGetSignature(t *testing.T) {
	options := RequestOptions{
		secretAccessKey: "my-key",
		region:          "my-region",
	}

	signedReq := signedRequest{
		shortDate:    "20060102",
		stringToSign: "stringToSign",
	}

	actualResult := getSignature(options, signedReq)
	expectedResult := "6f53cee4d7512a91a7e94a9e5efa39907099b6008d5ec93312a8dc8f58b4b474"

	assertStringsEqual(actualResult, expectedResult, t)
}

func TestGetCanonicalRequest(t *testing.T) {
	options := RequestOptions{
		destinationPath: "my/dest/path",
		bucketName:      "my-bucket-name",
	}

	signedReq := signedRequest{
		signedPayload: "abcdefghijklmnopqrstuvwxyz",
		date:          "20060102T150405Z",
	}

	actualResult := getCanonicalRequest(options, signedReq)
	expectedResult := "8c7d85bad638f347a8857e680c9e6904ed02ab7f79f469cc2b12e575390ff941"

	assertStringsEqual(actualResult, expectedResult, t)
}

func TestGetStringToSign(t *testing.T) {
	options := RequestOptions{
		region: "my-region",
	}

	signedReq := signedRequest{
		canonicalRequest: "8c7d85bad638f347a8857e680c9e6904ed02ab7f79f469cc2b12e575390ff941",
		date:             "20060102T150405Z",
		shortDate:        "20060102",
	}

	actualResult := getStringToSign(options, signedReq)
	expectedResult := "AWS4-HMAC-SHA256\n20060102T150405Z\n20060102/my-region/s3/aws4_request\n8c7d85bad638f347a8857e680c9e6904ed02ab7f79f469cc2b12e575390ff941"

	assertStringsEqual(actualResult, expectedResult, t)
}

func TestSha256hex(t *testing.T) {
	actualResult := sha256hex([]byte("The payload"))
	expectedResult := "664d8179447dd3a5b7b1cb6e00760a80593b0244c0f152aee482ed8c230099df"

	assertStringsEqual(actualResult, expectedResult, t)
}

func TestHmacSHA256(t *testing.T) {
	key := []byte("My key as a byte slice")
	content := "This is the string to hash"
	// Calculated using: http://jetcityorange.com/hmac/
	expectedResult := "979a44859ec6195631c0318006915a5e5542b79ec9a67480d0b41fdba0b6956d"
	hmacSHA256 := hmacSHA256(key, content)
	actualResult := hex.EncodeToString(hmacSHA256)

	assertStringsEqual(actualResult, expectedResult, t)

}
