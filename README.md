# csharp-signing

## Quickstart

```
ln -s ~/path/to/UAT_signing.crt sign.crt
ln -s ~/path/to/UAT_signing.key sign.key
# sign the bytes "foo" using the key sign.key
dotnet run -- sign -d foo 
# verify that the bytes "foo" were signed with "<base64 signature>"
dotnet run -- verify -d foo -s "<base64 signature>"
```
