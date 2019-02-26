import * as crypto from "./crypto";
import * as suites from './suites';
import * as serialization from './serialization';

export const VERSION = 0;

export interface TimePeroid {
    /* Time periods conists of two 32bit integers in unix time*/
    start: number,
    end: number
}

export interface Certificate {
    version: number,
    subject: string,
    validity: TimePeroid,
    signature: crypto.Signature
}

export class MC {

    readonly suite: suites.Suite;
    readonly crypto: crypto.Crypto;

    constructor(cryptoSuite: string) {

        switch (cryptoSuite) {
            case 'p192':
                this.suite = suites.P192SHA256;
                break;
            case 'p256':
                this.suite = suites.P256SHA256;
                break;
            default:
                throw new Error('unkown cypher suite');
        }

        this.crypto = new crypto.Crypto(this.suite);
    };

    public newPrivateKey(): string {

        const key = this.crypto.generatePrivateKey();
        return serialization.serializePrivateKey(key);
    }

    public computePublicKeyFromPrivateKey(privateKey: string): string {

        const privKey = serialization.dezerializePrivateKey(privateKey);
        const pubKey = this.crypto.publicFromPrivate(privKey);
        return serialization.serializePublicKey(pubKey);

    }

    public signCertificate(
        subjectName: string,
        subjectPublicKey: string,
        validity: TimePeroid,
        issuerPrivateKey: string,
    ): string {

        const pubKey = serialization.deserializePublicKey(subjectPublicKey);
        const privKey = serialization.dezerializePrivateKey(issuerPrivateKey);

        const signedData = canocializeSignedData(VERSION, subjectName, pubKey, validity);
        const signature = this.crypto.sign(signedData, privKey);

        const certificate = {
            version: VERSION,
            subject: subjectName,
            validity: validity,
            signature: signature
        }

        return serialization.serializeCertificate(certificate);
    }

    public sign(message: string, privateKey: string): string {

        const privKey = serialization.dezerializePrivateKey(privateKey);
        const signature = this.crypto.sign(message, privKey);
        return serialization.serializeSignature(signature);
    }

    public verifySignature(
        subjectName: string,
        message: string,
        signature: string,
        certificate: string,
        caPublicKey: string
    ) {

        const sign = serialization.deserializeSignature(signature);
        const cert = serialization.deserializeCertificate(certificate);
        const pubKey = serialization.deserializePublicKey(caPublicKey);

        // Calculate the public key which verifies the signature
        const publicKey = this.crypto.recoverPublicKey(message, sign);

        // Reassmble the certificate data
        const signedData = canocializeSignedData(cert.version, subjectName, publicKey, cert.validity);

        const isvalid = this.crypto.verify(signedData, cert.signature, pubKey);
        return isvalid;
    }
}

function canocializeSignedData(
    version: number,
    subjectName: string,
    subjectPublicKey: crypto.PublicKey,
    validity: TimePeroid) {

    return version + "+" + subjectName + "+" + subjectPublicKey.hash + "+" + validity.start + "+" + validity.end;
}
