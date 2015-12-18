# authtoken

Extract the token from request Authorization headers.

```go
// get token from Authorization header from *http.Request
authToken, err := authtoken.FromRequest(req)
```
