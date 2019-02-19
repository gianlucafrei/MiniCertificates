import {Certificate} from "./main";

var msgpack = require("msgpack-lite");
const BN = require('bn.js');

function hexStringToBinary(s: string) : Buffer{

    const number = new BN(s, 16);
    const buffer = number.toArrayLike(Buffer)
    return buffer
}

function binaryToHexString(data: Buffer) : string{

    const number = new BN(data);
    const hexStr = number.toString(16);
    return hexStr;
}

export function serializeCertificate(certificate: Certificate) : Buffer{

    const doc = {
        v: certificate.version,
        s: certificate.subject,
        vs:certificate.validity.start,
        ve:certificate.validity.end,
        sr: hexStringToBinary(certificate.signature.r),
        ss: hexStringToBinary(certificate.signature.s),
        sj: certificate.signature.j
    }

    var buffer = msgpack.encode(doc);
    return buffer;
}

export function deserializeCertificate(packedCertificate : Buffer) : Certificate{

    const doc = msgpack.decode(packedCertificate);

    const certificate = {
        version: doc.v,
        subject: doc.s,
        validity: {start: doc.vs, end: doc.ve},
        signature: {r: binaryToHexString(doc.sr), s: binaryToHexString(doc.ss), j: doc.sj}
    }

    return certificate;
}