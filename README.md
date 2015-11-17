# authtoken

Used to extract the Authorization tokend from request headers.

```go
// get token from Authorization header from *http.Request
authToken, err := authtoken.FromRequest(req)
```
