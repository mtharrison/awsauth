package v4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"github.com/mtharrison/s3p/files"
	"github.com/mtharrison/s3p/settings"
	"io/ioutil"
	"log"
	"time"
)

// authorizationHeaderComponents contains the fields needed to build an
// authorization header
type authorizationHeaderComponents struct {
	algorithm     string
	accessKey     string
	date          string
	region        string
	signedHeaders string
	signature     string
}

func GetHeaders(file files.File, settings settings.CommandSettings) map[string]string {

	// 3 stage process from http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

	// Task 1: Create a Canonical Request

	bagbytes, err := ioutil.ReadFile(file.Path)

	if err != nil {
		log.Fatal(err)
	}

	hash := sha256.Sum256(bagbytes)

	signedPayload := hex.EncodeToString(hash[:])

	xdate := time.Now().UTC().Format("20060102T150405Z")

	canonicalRequest := "PUT\n" +
		"/" + settings.DestinationPath + file.Path + "\n" +
		"\n" +
		"host:" + settings.BucketName + ".s3.amazonaws.com\n" +
		"x-amz-content-sha256:" + signedPayload + "\n" +
		"x-amz-date:" + xdate + "\n" +
		"\n" +
		"host;x-amz-content-sha256;x-amz-date\n" +
		signedPayload

	hashedCanonicalRequest := sha256.Sum256([]byte(canonicalRequest))
	hashedCanonicalRequestString := hex.EncodeToString(hashedCanonicalRequest[:])

	// Task 2: Create a String to Sign

	stringToSign := "AWS4-HMAC-SHA256\n" +
		xdate + "\n" +
		time.Now().Format("20060102") + "/" + settings.Region + "/s3/aws4_request" + "\n" +
		hashedCanonicalRequestString

	// Task 3: Calculate Signature

	//Make the signing key
	step1 := hmacSHA256([]byte("AWS4"+settings.SecretAccessKey), time.Now().UTC().Format("20060102"))
	step2 := hmacSHA256(step1, settings.Region)
	step3 := hmacSHA256(step2, "s3")
	signingKey := hmacSHA256(step3, "aws4_request")

	// Compute the signature
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	c := authorizationHeaderComponents{
		algorithm:     "AWS4-HMAC-SHA256",
		accessKey:     settings.AccessKeyID,
		date:          time.Now().UTC().Format("20060102"),
		region:        settings.Region,
		signedHeaders: "host;x-amz-content-sha256;x-amz-date",
		signature:     signature,
	}

	// Make the header
	header := buildAuthorizationHeaderValue(c)

	retMap := map[string]string{
		"Authorization":        header,
		"Host":                 settings.BucketName + ".s3.amazonaws.com",
		"x-amz-content-sha256": signedPayload,
		"x-amz-date":           xdate,
	}

	return retMap
}

// hmacSHA256 calculates the hmacSHA256 from a key (slice of bytes) and a
// message string. It returns a slice of bytes.
func hmacSHA256(key []byte, content string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}

// buildAuthorizationHeaderValue creates the string which will be used as the
// authorization header in the request to AWS.
// See: http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-auth-using-authorization-header.html
func buildAuthorizationHeaderValue(c authorizationHeaderComponents) string {
	return c.algorithm + " Credential=" + c.accessKey + "/" + c.date + "/" +
		c.region + "/s3/aws4_request" +
		",SignedHeaders=" + c.signedHeaders + ",Signature=" + c.signature
}
