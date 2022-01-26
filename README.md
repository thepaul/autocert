# thepaul/autocert

This is mostly just a wrapper around the golang.org/x/crypto/acme/autocert module, which streamlines
usage somewhat for the cases I tend to need. In particular, it allows having your SSL server listen
on a local port other than 443 (although it's still necessary for the ACME server to be able to
contact the server externally on 443).

## Example usage

```go
manager := autocert.NewTLSAutoCertManager(func(ctx context.Context, hostName string) error {
    if hostName != expectedHostName {
        return fmt.Errorf("invalid hostname %q", hostName)
    }
    return nil
}, "my@email.com", time.Hour * 24, "/my/cache/directory")

httpsListener, err := manager.Listen("tcp", "0.0.0.0:8443")
if err != nil {
    panic(err)
}
log.Fatal(httpServer.Serve(httpsListener))
```
