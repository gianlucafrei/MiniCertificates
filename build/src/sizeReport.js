"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const suites_1 = require("../src/suites");
const main_1 = require("../src/main");
console.log("Suite   Secret Key   Public Key   Certificate");
suites_1.ALL.forEach(suite => {
    const mc = new main_1.MC(suite.name, main_1.MC.insecureRandom);
    const caPrivate = mc.newPrivateKey();
    const userPrivate = mc.newPrivateKey();
    const userPublic = mc.computePublicKeyFromPrivateKey(userPrivate);
    const validityStart = mc.now();
    const vallidityEnd = mc.plus(validityStart, 1, 0, 0, 0, 0, 0);
    const certificate = mc.signCertificate("user", userPublic, validityStart, vallidityEnd, caPrivate);
    const privateKeySize = userPrivate.length / 2;
    const publicKeySize = userPublic.length / 2;
    const certificateSize = certificate.length / 2;
    console.log('%s      %d         %d           %d', suite.name, privateKeySize, publicKeySize, certificateSize);
});
//# sourceMappingURL=sizeReport.js.map