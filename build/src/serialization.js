"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
var msgpack = require("msgpack-lite");
const BN = require('bn.js');
function hexStringToBuffer(s) {
    const number = new BN(s, 16);
    const buffer = number.toArrayLike(Buffer);
    return buffer;
}
function bufferToHexString(data) {
    const number = new BN(data);
    const hexStr = number.toString(16);
    return hexStr.toString('hex');
}
function serializeCertificate(certificate) {
    const doc = {
        v: certificate.version,
        s: certificate.subject,
        t: certificate.validity.start,
        e: certificate.validity.end,
        r: hexStringToBuffer(certificate.signature.r),
        u: hexStringToBuffer(certificate.signature.s),
        j: certificate.signature.j
    };
    var buffer = msgpack.encode(doc);
    return bufferToHexString(buffer);
}
exports.serializeCertificate = serializeCertificate;
function deserializeCertificate(serializedCertificate) {
    const packedCertificate = hexStringToBuffer(serializedCertificate);
    const doc = msgpack.decode(packedCertificate);
    const certificate = {
        version: doc.v,
        subject: doc.s,
        validity: { start: doc.t, end: doc.e },
        signature: { r: bufferToHexString(doc.r), s: bufferToHexString(doc.u), j: doc.j }
    };
    return certificate;
}
exports.deserializeCertificate = deserializeCertificate;
function serializePrivateKey(key) {
    return key.x;
}
exports.serializePrivateKey = serializePrivateKey;
function deserializePrivateKey(serializedKey) {
    return { x: serializedKey };
}
exports.deserializePrivateKey = deserializePrivateKey;
function serializePublicKey(key) {
    return key.hash;
}
exports.serializePublicKey = serializePublicKey;
function deserializePublicKey(serializedKey) {
    return { hash: serializedKey };
}
exports.deserializePublicKey = deserializePublicKey;
function serializeSignature(signature) {
    var buffer = msgpack.encode(signature);
    return bufferToHexString(buffer);
}
exports.serializeSignature = serializeSignature;
function deserializeSignature(serializedSignature) {
    var buffer = hexStringToBuffer(serializedSignature);
    return msgpack.decode(buffer);
}
exports.deserializeSignature = deserializeSignature;
//# sourceMappingURL=serialization.js.map