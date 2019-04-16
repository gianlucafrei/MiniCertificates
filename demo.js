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