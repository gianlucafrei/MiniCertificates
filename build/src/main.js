"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const crypto = require("./crypto");
const suites = require("./suites");
const serialization = require("./serialization");
class MC {
    constructor(cryptoSuite, randomFunction) {
        this.VERSION = 0;
        switch (cryptoSuite) {
            case 'p192':
                this.suite = suites.P192SHA256;
                break;
            case 'p256':
                this.suite = suites.P256SHA256;
                break;
            default:
                throw new Error('unknown cypher suite');
        }
        this.crypto = new crypto.Crypto(this.suite, randomFunction);
    }
    ;
    newPrivateKey() {
        const key = this.crypto.generatePrivateKey();
        return serialization.serializePrivateKey(key);
    }
    computePublicKeyFromPrivateKey(privateKey) {
        const privKey = serialization.deserializePrivateKey(privateKey);
        const pubKey = this.crypto.publicFromPrivate(privKey);
        return serialization.serializePublicKey(pubKey);
    }
    signCertificate(subjectName, subjectPublicKey, validityStart, validityEnd, issuerPrivateKey) {
        const validity = { start: validityStart, end: validityEnd };
        const pubKey = serialization.deserializePublicKey(subjectPublicKey);
        const privKey = serialization.deserializePrivateKey(issuerPrivateKey);
        const signedData = canonicalizeCertificateData(this.VERSION, subjectName, pubKey, validity);
        const signature = this.crypto.sign(signedData, privKey);
        const certificate = {
            version: this.VERSION,
            subject: subjectName,
            validity: validity,
            signature: signature
        };
        return serialization.serializeCertificate(certificate);
    }
    sign(message, privateKey) {
        const privKey = serialization.deserializePrivateKey(privateKey);
        const signature = this.crypto.sign(message, privKey);
        return serialization.serializeSignature(signature);
    }
    recoverSignerPublicKey(message, signature) {
        const sign = serialization.deserializeSignature(signature);
        const pk = this.crypto.recoverPublicKey(message, sign);
        return serialization.serializePublicKey(pk);
    }
    verifySignatureWithPublicKey(message, signature, publicKey) {
        const sign = serialization.deserializeSignature(signature);
        const pk = serialization.deserializePublicKey(publicKey);
        return this.crypto.verify(message, sign, pk);
    }
    verifySignatureWithCertificate(subjectName, message, signature, certificate, trustedCaPublicKeys) {
        const sign = serialization.deserializeSignature(signature);
        const cert = serialization.deserializeCertificate(certificate);
        var now = this.now();
        if (now < cert.validity.start || now > cert.validity.end)
            return false;
        const publicKey = this.crypto.recoverPublicKey(message, sign);
        const certificateSignedData = canonicalizeCertificateData(cert.version, subjectName, publicKey, cert.validity);
        const validPublicKeyForCertificate = serialization.serializePublicKey(this.crypto.recoverPublicKey(certificateSignedData, cert.signature));
        const isValid = (trustedCaPublicKeys.indexOf(validPublicKeyForCertificate) > -1);
        return isValid;
    }
    getAuthenticSigner(message, signature, certificate, trustedCaPublicKeys) {
        var claimedName = this.getUsernameOfCertificate(certificate);
        var isValid = this.verifySignatureWithCertificate(claimedName, message, signature, certificate, trustedCaPublicKeys);
        if (isValid)
            return claimedName;
        else
            return null;
    }
    getUsernameOfCertificate(certificate) {
        var cert = serialization.deserializeCertificate(certificate);
        return cert.subject;
    }
    dateToUnixTime(date) {
        return Math.floor(date.getTime() / 1000);
    }
    now() {
        return this.dateToUnixTime(new Date());
    }
    ;
    plus(timestamp, years = 0, months = 0, days = 0, hours = 0, minutes = 0, seconds = 0) {
        var date = new Date(timestamp * 1000);
        date.setFullYear(date.getFullYear() + years);
        date.setMonth(date.getMonth() + months);
        date.setDate(date.getDate() + days);
        date.setHours(date.getHours() + hours);
        date.setMinutes(date.getMinutes() + minutes);
        date.setSeconds(date.getSeconds() + seconds);
        return this.dateToUnixTime(date);
    }
    static insecureRandom(n) {
        return Array.from({ length: n }, () => Math.floor(Math.random() * 256));
    }
}
exports.MC = MC;
function canonicalizeCertificateData(version, subjectName, subjectPublicKey, validity) {
    return version + "+" + subjectName + "+" + subjectPublicKey.hash + "+" + validity.start + "+" + validity.end;
}
module.exports = MC;
//# sourceMappingURL=main.js.map