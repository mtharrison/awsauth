package v4

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

const (
	ALGORITHM      string = "AWS4-HMAC-SHA256"
	SIGNED_HEADERS string = "host;x-amz-content-sha256;x-amz-date"
)

// RequestOptions hold the options set by the user of this package
type RequestOptions struct {
	payload         []byte
	destinationPath string
	bucketName      string
	region          string
	secretAccessKey string
	accessKeyID     string
}

// signedRequest hold the values of the various pieces data that are created
// and required to arrive at the final authorization headers
type signedRequest struct {
	signedPayload    string
	date             string
	shortDate        string
	canonicalRequest string
	signature        string
	stringToSign     string
}

// GetHeaders returns a map of headers, to then be used as part of a request to
// aws
func GetHeaders(options RequestOptions) map[string]string {

	// 3 stage process from http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html

	// Task 1: Create a Canonical Request
	signedReq := signedRequest{}
	signedReq.signedPayload = sha256hex(options.payload)
	signedReq.date = getAmazonDate()
	signedReq.shortDate = getAmazonShortDate()
	signedReq.canonicalRequest = getCanonicalRequest(options, signedReq)

	// Task 2: Create a String to Sign
	signedReq.stringToSign = getStringToSign(options, signedReq)

	// Task 3: Calculate Signature
	signedReq.signature = getSignature(options, signedReq)

	// Build the auth header
	authHeader := getAuthorizationHeader(options, signedReq)

	// Prepare map of headers
	headers := map[string]string{
		"Authorization":        authHeader,
		"Host":                 options.bucketName + ".s3.amazonaws.com",
		"x-amz-content-sha256": signedReq.signedPayload,
		"x-amz-date":           signedReq.date,
	}

	return headers
}

// getAuthorizationHeader creates the string which will be used as the
// authorization header in the request to AWS
func getAuthorizationHeader(options RequestOptions, signedReq signedRequest) string {
	return ALGORITHM + " Credential=" + options.accessKeyID + "/" +
		signedReq.date + "/" + options.region + "/s3/aws4_request" +
		",SignedHeaders=" + SIGNED_HEADERS + ",Signature=" + signedReq.signature
}

func getSignature(options RequestOptions, signedReq signedRequest) string {
	step1 := hmacSHA256([]byte("AWS4"+options.secretAccessKey), signedReq.shortDate)
	step2 := hmacSHA256(step1, options.region)
	step3 := hmacSHA256(step2, "s3")
	signingKey := hmacSHA256(step3, "aws4_request")

	return hex.EncodeToString(hmacSHA256(signingKey, signedReq.stringToSign))
}

func getCanonicalRequest(options RequestOptions, signedReq signedRequest) string {
	requestString := "PUT\n" + "/" + options.destinationPath + "\n\n" +
		"host:" + options.bucketName + ".s3.amazonaws.com\n" +
		"x-amz-content-sha256:" + signedReq.signedPayload + "\n" +
		"x-amz-date:" + signedReq.date + "\n\n" +
		"host;x-amz-content-sha256;x-amz-date\n" + signedReq.signedPayload

	return sha256hex([]byte(requestString))
}

func getStringToSign(options RequestOptions, signedReq signedRequest) string {
	return "AWS4-HMAC-SHA256\n" + signedReq.date + "\n" +
		signedReq.shortDate + "/" + options.region + "/s3/aws4_request" + "\n" +
		signedReq.canonicalRequest
}

// getAmazonDate returns the current date in the format required by amazon
// 20060102T150405Z
func getAmazonDate() string {
	return time.Now().UTC().Format("20060102T150405Z")
}

// getAmazonShortDate returns the current date in the format required by amazon
// 20060102
func getAmazonShortDate() string {
	return time.Now().Format("20060102")
}

// sha256hex converts the data into a hex encoded sha256 hash
func sha256hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// hmacSHA256 calculates the hmacSHA256 from a key (slice of bytes) and a
// message string. It returns a slice of bytes.
func hmacSHA256(key []byte, content string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(content))
	return mac.Sum(nil)
}
