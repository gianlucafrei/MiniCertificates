import {Certificate} from "./main";

var msgpack = require("msgpack-lite");
const BN = require('bn.js');

function hexStringToBinary(s: string){

    const number = new BN(s, 16);
    const buffer = number.toArrayLike(Buffer, 'le')
    return buffer
}

export function serializeCertificate(certificate: Certificate) : string{

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
