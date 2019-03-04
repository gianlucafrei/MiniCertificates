import {Certificate} from "./main";
import { PrivateKey, PublicKey, Signature } from './crypto';

var msgpack = require("msgpack-lite");
const BN = require('bn.js');

function hexStringToBuffer(s: string) : Buffer{

    const number = new BN(s, 16);
    const buffer = number.toArrayLike(Buffer)
    return buffer
}

function bufferToHexString(data: Buffer) : string{

    const number = new BN(data);
    const hexStr = number.toString(16);
    return hexStr.toString('hex');
}

export function serializeCertificate(certificate: Certificate) : string{

    // Copy attributes to avoid long the long names, this saves some bytes
    const doc = {
        v: certificate.version,
        s: certificate.subject,
        t:certificate.validity.start,
        e:certificate.validity.end,
        r: hexStringToBuffer(certificate.signature.r),
        u: hexStringToBuffer(certificate.signature.s),
        j: certificate.signature.j
    }

    var buffer : Buffer = msgpack.encode(doc);
    return bufferToHexString(buffer);
}

export function deserializeCertificate(serializedCertificate : string) : Certificate{

    const packedCertificate = hexStringToBuffer(serializedCertificate);
    const doc = msgpack.decode(packedCertificate);

    const certificate = {
        version: doc.v,
        subject: doc.s,
        validity: {start: doc.t, end: doc.e},
        signature: {r: bufferToHexString(doc.r), s: bufferToHexString(doc.u), j: doc.j}
    }

    return certificate;
}

export function serializePrivateKey(key:PrivateKey):string{

    return key.x;
}

export function deserializePrivateKey(serializedKey:string):PrivateKey{
 
    return {x:serializedKey};
}

export function serializePublicKey(key:PublicKey):string{

    return key.hash;
}

export function deserializePublicKey(serializedKey:string):PublicKey{

    return {hash:serializedKey};
}

export function serializeSignature(signature:Signature):string{

    var buffer : Buffer = msgpack.encode(signature);
    return bufferToHexString(buffer);

}

export function deserializeSignature(serializedSignature:string):Signature{

    var buffer : Buffer = hexStringToBuffer(serializedSignature);
    return msgpack.decode(buffer);

}