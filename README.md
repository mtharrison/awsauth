#AWSAUTH

##Usage
		

    package main
    
    import "github.com/mtharrison/awsauth/v4"
    
    func main() {
        options := v4.RequestOptions{
            payload:         []byte("My Payload"), // A slice of bytes
            destinationPath: "my/upload/path",
            bucketName:      "my-bucket",
            region:          "my-region",
            secretAccessKey: "my-key",
            accessKeyID:     "my-key-id",
        }
    
        headers := v4.GetHeaders(options)    
    }
    
The return value of `GetHeaders` is a `map[string]string` with the following keys:

- Authorization
- Host
- x-amz-content-sha256
- x-amz-date

These headers can then be used to build a request to AWS.

##Supported versions

- v4