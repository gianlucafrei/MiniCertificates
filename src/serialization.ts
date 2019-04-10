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

    // check that s has the same size as r 
    if(signature.s.length != signature.r.length)
        throw new Error('signature s has not the same length as r');

    if(signature.j > 4)
        throw new Error('invalid singature j');

    // For efficiency we just concat all signature parts
    let hexstr = signature.s + signature.r;
    hexstr += '0' + signature.j;

    return hexstr;

}

export function deserializeSignature(serializedSignature:string):Signature{

    if(serializedSignature.length % 2 != 0)
        throw new Error('invalid hex string')

    let n = serializedSignature.length;

    let shex = serializedSignature.substring(0,(n-2)/2);
    let rhex = serializedSignature.substring((n-2)/2,(n-2));
    let jhex = serializedSignature.substring((n-2), n);

    return {
        s: shex,
        r: rhex,
        j: parseInt(jhex, 16)
    };
}