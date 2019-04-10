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
    let s = signature.s;
    let r = signature.r;
    let j = signature.j;
    if (s.length % 2 == 1)
        s = '0' + s;
    if (r.length % 2 == 1)
        r = '0' + r;
    if (s.length != r.length)
        throw new Error('signature s has not the same length as r');
    if (j > 4)
        throw new Error('invalid singature j');
    let hexstr = s + r;
    hexstr += '0' + j;
    return hexstr;
}
exports.serializeSignature = serializeSignature;
function deserializeSignature(serializedSignature) {
    if (serializedSignature.length % 2 != 0)
        throw new Error('invalid hex string');
    let n = serializedSignature.length;
    let shex = serializedSignature.substring(0, (n - 2) / 2);
    let rhex = serializedSignature.substring((n - 2) / 2, (n - 2));
    let jhex = serializedSignature.substring((n - 2), n);
    if (shex[0] == '0')
        shex = shex.substring(1, shex.length);
    if (rhex[0] == '0')
        rhex = rhex.substring(1, rhex.length);
    return {
        s: shex,
        r: rhex,
        j: parseInt(jhex, 16)
    };
}
exports.deserializeSignature = deserializeSignature;
//# sourceMappingURL=serialization.js.map