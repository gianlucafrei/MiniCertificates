"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const BN = require('bn.js');
class Crypto {
    constructor(suite, randomFunction) {
        this.suite = suite;
        this.suite.ec.rand = randomFunction;
        this.random = randomFunction;
    }
    ;
    privateKeyFromSecret(secret) {
        const keyPair = this.suite.ec.keyPair({ priv: secret });
        const exponent = keyPair.getPrivate('hex');
        return { x: exponent };
    }
    ;
    generatePrivateKey() {
        const entropy = this.random(this.suite.curvelenght);
        const key = this.suite.ec.genKeyPair({ entropy: entropy });
        const exponent = key.getPrivate('hex');
        return { x: exponent };
    }
    publicFromPrivate(privateKey) {
        const keyPair = this.suite.ec.keyPair({ priv: privateKey.x });
        const pubPointAsString = this.canonizeCurvePoint(keyPair.getPublic());
        const hash = this.hashMessage(pubPointAsString);
        return { hash: hash };
    }
    sign(message, privateKey) {
        const digest = this.hashMessage(message);
        const key = this.suite.ec.keyPair({ priv: privateKey.x });
        const signature = key.sign(digest);
        return {
            r: signature.r.toString(16),
            s: signature.s.toString(16),
            j: signature.recoveryParam
        };
    }
    recoverPublicKey(message, signature) {
        const digest = this.hashMessage(message);
        var digestBase10 = (new BN(digest, 16)).toString();
        var recoveredPoint = this.suite.ec.recoverPubKey(digestBase10, signature, signature.j, 'object');
        var pointAsString = this.canonizeCurvePoint(recoveredPoint);
        const hash = this.hashMessage(pointAsString);
        return { hash: hash };
    }
    verify(message, signature, publicKey) {
        const recoveredPubkey = this.recoverPublicKey(message, signature);
        return publicKey.hash == recoveredPubkey.hash;
    }
    canonizeCurvePoint(point) {
        return point.x.toString(16) + ":" + point.y.toString(16);
    }
    hashMessage(message) {
        const digest = this.suite.hashfunction.hex(message);
        return digest.substring(0, this.suite.curvelenght / 4);
    }
}
exports.Crypto = Crypto;
//# sourceMappingURL=crypto.js.map