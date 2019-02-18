import * as crypto from "./crypto"

export const VERSION = 0;

export interface TimePeroid{
    /* Time periods conists of two 32bit integers in unix time*/
    start: number,
    end: number
}

export interface Certificate{
    version: number,
    subject: string,
    validity: TimePeroid,
    signature: crypto.Signature
}

export function newPrivateKey() : crypto.PrivateKey{

    return crypto.generatePrivateKey();
}

export function computePublicKeyFromPrivateKey(privateKey: crypto.PrivateKey) : crypto.PublicKey{

    return crypto.publicFromPrivate(privateKey)
}

export function signCertificate(
    subjectName: string,
    subjectPublicKey: crypto.PublicKey,
    validity: TimePeroid,
    issuerPrivateKey: crypto.PrivateKey) : Certificate{

    const signedData = canocializeSignedData(VERSION, subjectName, subjectPublicKey, validity);
    const signature = crypto.sign(signedData, issuerPrivateKey);

    const certificate = {
        version: VERSION,
        subject: subjectName,
        validity: validity,
        signature: signature
    }

    return certificate;
}

export function sign(message: string, privateKey: crypto.PrivateKey) : crypto.Signature{

    return crypto.sign(message, privateKey);
}

export function verifySignature(subjectName: string, message: string, signature: crypto.Signature, certificate: Certificate, caPublicKey: crypto.PublicKey){

    // Calculate the public key which verifies the signature
    const publicKey = crypto.recoverPublicKey(message, signature);

    // Reassmble the certificate data
    const signedData = canocializeSignedData(certificate.version, subjectName, publicKey, certificate.validity);

    const isvalid = crypto.verify(signedData, certificate.signature, caPublicKey);
    return isvalid;
}


function canocializeSignedData(version: number, subjectName: string, subjectPublicKey: crypto.PublicKey, validity: TimePeroid){

    return version + "+" +  subjectName + "+" + subjectPublicKey.hash + "+" + validity.start + "+" + validity.end;
}