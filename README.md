# MiniCertificates
This is a proof of concept. Don't use this library in a real-world application.

## What is a mini certificate
MiniCertificates work like normal public key certificates but are much smaller.
For a 100bit security level, a public key certificate can be less than 100 bytes in size.
MiniCertificates only support ECDSA keys. This is because when using ECDSA, you can recover the public key if you have a signature and message.

## How does it work
Unlike a normal public key certificate, the key itself is not stored in a MiniCertificate. To verify the validity of a certificate, the verifier first needs to recover the public key from a signature, and can then check if the signature of the MiniCertificate is valid.

## Quickstart

```
npm install
npm run build
npm run test
```
