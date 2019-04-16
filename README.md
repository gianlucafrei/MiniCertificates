# MiniCertificates
This is a proof of concept. Don't use this library in a real-world application.

## What is a mini certificate
MiniCertificates work like normal public key certificates but are much smaller.
For a 100bit security level, a public key certificate can be less than 100 bytes in size.
MiniCertificates only support ECDSA keys. This is because when using ECDSA, you can recover the public key if you have a signature and message.

## How does it work
Unlike a normal public key certificate, the key itself is not stored in a MiniCertificate. To verify the validity of a certificate, the verifier first needs to recover the public key from a signature, and can then check if the signature of the MiniCertificate is valid.

## Size of the certificate

The size of the certificate depends on the cipher suite used and length of the username.
This tables lists all supported suites and the sizes of the keys, signature and certificates in bytes.

| Suite | Secret Key | Public Key | Certificate | Singature |
+-------+------------+------------+-------------+-----------+
| p192  | 24         | 24         | 84          | 49        |
| p256  | 32         | 32         | 100         | 65        |
+-------+------------+------------+-------------+-----------+

## How to use this library

```
npm install gianlucafrei/MiniCertificates
```

All inputs are strings.
All outputs are hexdecimal numbers as strings.

```
var minicert = require('./build/src/main.js');
var mc = new minicert('p256', minicert.insecureRandom);

// Create key pair for the issuer of the certificate
var caSecret = mc.newPrivateKey();
var caPublic = mc.computePublicKeyFromPrivateKey(caSecret);
console.log("CA secret: " + caSecret);
console.log("CA public: " + caPublic);

// Create key pair for user
var userSecret = mc.newPrivateKey();
var userPublic = mc.computePublicKeyFromPrivateKey(userSecret);

// Sign the certificate
var username = "pirate";
var validityStart = mc.now();
var validityEnd = mc.plus(validityStart)
var certificate = mc.signCertificate(username, userPublic, validityStart, validityEnd, caSecret);
console.log("Certificate value: " + certificate);

// user signs a message
var message = "This is a message";
var signature = mc.sign(message, userSecret);
console.log("Signature value: " + signature);

// Test the validity of the signature with the certificate
var expectedUser = "pirate";
var isValid = mc.verifySignatureWithCertificate(expectedUser, message, signature, certificate, caPublic);
console.log("Is a valid signature: " + isValid);
```