import { Crypto, Signature, PrivateKey, PublicKey } from "./crypto";
import * as suites from './suites';

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
    signature: Signature
}

export class MC {

    readonly suite: suites.Suite;
    readonly crypto: Crypto;

    constructor(cryptoSuite: suites.Suite | string) {

        if (typeof cryptoSuite === 'string' || cryptoSuite instanceof String) {
            switch (cryptoSuite) {
                case 'p192':
                    this.suite = suites.P192SHA256;
                    break;
                case 'p256':
                    this.suite = suites.P256SHA256;
                    break;
                default:
                    throw new Error('unkown cyper suite');
            }
        }
        else {
            this.suite = cryptoSuite;
        }

        this.crypto = new Crypto(this.suite);
    };

    public newPrivateKey(): PrivateKey {

        return this.crypto.generatePrivateKey();
    }

    public computePublicKeyFromPrivateKey(privateKey: PrivateKey, ): PublicKey {

        return this.crypto.publicFromPrivate(privateKey)
    }

    public signCertificate(
        subjectName: string,
        subjectPublicKey: PublicKey,
        validity: TimePeroid,
        issuerPrivateKey: PrivateKey,
    ): Certificate {

        const signedData = canocializeSignedData(VERSION, subjectName, subjectPublicKey, validity);
        const signature = this.crypto.sign(signedData, issuerPrivateKey);

        const certificate = {
            version: VERSION,
            subject: subjectName,
            validity: validity,
            signature: signature
        }

        return certificate;
    }

    public sign(message: string, privateKey: PrivateKey, ): Signature {

        return this.crypto.sign(message, privateKey);
    }

    public verifySignature(
        subjectName: string,
        message: string,
        signature: Signature,
        certificate: Certificate,
        caPublicKey: PublicKey,
    ) {

        // Calculate the public key which verifies the signature
        const publicKey = this.crypto.recoverPublicKey(message, signature);

        // Reassmble the certificate data
        const signedData = canocializeSignedData(certificate.version, subjectName, publicKey, certificate.validity);

        const isvalid = this.crypto.verify(signedData, certificate.signature, caPublicKey);
        return isvalid;
    }
}

function canocializeSignedData(
    version: number,
    subjectName: string,
    subjectPublicKey: PublicKey,
    validity: TimePeroid) {

    return version + "+" + subjectName + "+" + subjectPublicKey.hash + "+" + validity.start + "+" + validity.end;
}
