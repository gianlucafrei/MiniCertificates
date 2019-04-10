"use strict";
let minicert = require("./main");
console.log("Suite   Secret Key   Public Key   Certificate  Signature");
let curves = ['p192', 'p256'];
curves.forEach(suite => {
    const mc = new minicert(suite, minicert.insecureRandom);
    const caPrivate = mc.newPrivateKey();
    const userPrivate = mc.newPrivateKey();
    const userPublic = mc.computePublicKeyFromPrivateKey(userPrivate);
    const validityStart = mc.now();
    const vallidityEnd = mc.plus(validityStart, 1, 0, 0, 0, 0, 0);
    const certificate = mc.signCertificate("user", userPublic, validityStart, vallidityEnd, caPrivate);
    const signature = mc.sign('foobar', userPrivate);
    const privateKeySize = userPrivate.length / 2;
    const publicKeySize = userPublic.length / 2;
    const certificateSize = certificate.length / 2;
    const signatureSize = signature.length / 2;
    console.log('%s      %d         %d           %d          %d', suite, privateKeySize, publicKeySize, certificateSize, signatureSize);
});
//# sourceMappingURL=sizeReport.js.map