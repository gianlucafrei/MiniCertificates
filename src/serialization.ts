import { Certificate } from "./certificate";
import { PrivateKey, PublicKey, Signature } from './crypto';

/**
 * This file handles the conversion of javascript representations
 * objects used in this library to hexstrings and vice versa.
 * For each type of object Certificate, Sigature, Keys... are a serialize and deserialize function found.
 * 
 * We use msgpack to serialize objects because it's very space efficient.
 */

var msgpack = require("msgpack-lite");
const BN = require('bn.js');

/**
 * Converts a hex string to a buffer object
 */
function hexStringToBuffer(s: string): Buffer {

    const number = new BN(s, 16);
    const buffer = number.toArrayLike(Buffer)
    return buffer
}

/**
 * 
 * @param data Converts a buffer object to a hex string
 */
function bufferToHexString(data: Buffer): string {

    const number = new BN(data);
    const hexStr = number.toString(16);
    return hexStr.toString('hex');
}

/**
 * Serializes a certificate
 * @param certificate The certificate object to serialize
 */
export function serializeCertificate(certificate: Certificate): string {

    // Copy attributes to avoid long the long names, this saves some bytes
    const doc = {
        v: certificate.version,
        s: certificate.subject,
        t: certificate.validity.start,
        e: certificate.validity.end,
        r: hexStringToBuffer(certificate.signature.r),
        u: hexStringToBuffer(certificate.signature.s),
        j: certificate.signature.j
    }

    var buffer: Buffer = msgpack.encode(doc);
    return bufferToHexString(buffer);
}

/**
 * Unpacks a serialized certificate object.
 * @param serializedCertificate 
 */
export function deserializeCertificate(serializedCertificate: string): Certificate {

    const packedCertificate = hexStringToBuffer(serializedCertificate);
    const doc = msgpack.decode(packedCertificate);

    const certificate = {
        version: doc.v,
        subject: doc.s,
        validity: { start: doc.t, end: doc.e },
        signature: { r: bufferToHexString(doc.r), s: bufferToHexString(doc.u), j: doc.j }
    }

    return certificate;
}

/**
 * Serializes a private key object
 * @param key The private key
 */
export function serializePrivateKey(key: PrivateKey): string {

    return key.x;
}

/**
 * Unpacks a serialized private key object.
 * @param serializedKey 
 */
export function deserializePrivateKey(serializedKey: string): PrivateKey {

    return { x: serializedKey };
}

/**
 * Serializes a public key object.
 */
export function serializePublicKey(key: PublicKey): string {

    return key.hash;
}

/**
 * Unpacks a serialized public key object.
 * @param serializedKey 
 */
export function deserializePublicKey(serializedKey: string): PublicKey {

    return { hash: serializedKey };
}

/**
 * Serializes a signature.
 * This function does not use msgpack for efficiency but
 * conncatinates the different part of the signature directly.
 * @param signature 
 */
export function serializeSignature(signature: Signature): string {

    let s = signature.s;
    let r = signature.r;
    let j = signature.j;

    // Pad hexstring with 0
    if (s.length % 2 == 1)
        s = '0' + s;

    if (r.length % 2 == 1)
        r = '0' + r;

    // check that s has the same size as r 
    if (s.length != r.length)
        throw new Error('signature s has not the same length as r');

    if (j > 4)
        throw new Error('invalid singature j');

    // For efficiency we just concat all signature parts
    let hexstr = s + r;
    hexstr += '0' + j;

    return hexstr;

}

/**
 * Unpacks a serialized signature object.
 * @param serializedSignature 
 */
export function deserializeSignature(serializedSignature: string): Signature {

    if (serializedSignature.length % 2 != 0)
        throw new Error('invalid hex string')

    let n = serializedSignature.length;

    let shex = serializedSignature.substring(0, (n - 2) / 2);
    let rhex = serializedSignature.substring((n - 2) / 2, (n - 2));
    let jhex = serializedSignature.substring((n - 2), n);

    // Remove useless 0
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