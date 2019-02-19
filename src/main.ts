import {P192SHA256, Crypto, Signature, PrivateKey, PublicKey} from "./crypto"

let suite = P192SHA256;
let crypto = new Crypto(suite);

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
    signature: Signature
}

export function newPrivateKey() : PrivateKey{

    return crypto.generatePrivateKey();
}

export function computePublicKeyFromPrivateKey(privateKey: PrivateKey, ) : PublicKey{

    return crypto.publicFromPrivate(privateKey)
}

export function signCertificate(
    subjectName: string,
    subjectPublicKey: PublicKey,
    validity: TimePeroid,
    issuerPrivateKey: PrivateKey,
    ) : Certificate{

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

export function sign(message: string, privateKey: PrivateKey, ) : Signature{

    return crypto.sign(message, privateKey);
}

export function verifySignature(
    subjectName: string,
    message: string,
    signature: Signature,
    certificate: Certificate,
    caPublicKey: PublicKey,
    ){

    // Calculate the public key which verifies the signature
    const publicKey = crypto.recoverPublicKey(message, signature);

    // Reassmble the certificate data
    const signedData = canocializeSignedData(certificate.version, subjectName, publicKey, certificate.validity);

    const isvalid = crypto.verify(signedData, certificate.signature, caPublicKey);
    return isvalid;
}

function canocializeSignedData(
    version: number,
    subjectName: string,
    subjectPublicKey: PublicKey,
    validity: TimePeroid){

    return version + "+" +  subjectName + "+" + subjectPublicKey.hash + "+" + validity.start + "+" + validity.end;
}
