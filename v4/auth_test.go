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

func TestHmacSHA256(t *testing.T) {
	key := []byte("My key as a byte slice")
	content := "This is the string to hash"
	// Calculated using: http://jetcityorange.com/hmac/
	expectedResult := "979a44859ec6195631c0318006915a5e5542b79ec9a67480d0b41fdba0b6956d"
	hmacSHA256 := hmacSHA256(key, content)
	actualResult := hex.EncodeToString(hmacSHA256)

	assertStringsEqual(actualResult, expectedResult, t)

}

func TestBuildAuthorizationHeaderValue(t *testing.T) {
	c := authorizationHeaderComponents{
		algorithm:     "AWS4-HMAC-SHA256",
		accessKey:     "my-access-key",
		date:          "20060102",
		region:        "the-region",
		signedHeaders: "host;x-amz-content-sha256;x-amz-date",
		signature:     "asignature",
	}
	actualResult := buildAuthorizationHeaderValue(c)
	expectedResult := "AWS4-HMAC-SHA256 Credential=my-access-key/20060102/the-region/s3/aws4_request,SignedHeaders=host;x-amz-content-sha256;x-amz-date,Signature=asignature"

	assertStringsEqual(actualResult, expectedResult, t)
}
