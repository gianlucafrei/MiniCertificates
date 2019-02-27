import * as crypto from "./crypto";
import * as suites from './suites';
import * as serialization from './serialization';

interface TimePeroid {
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

    readonly VERSION = 0;
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
        validityStart: number,
        validityEnd: number,
        issuerPrivateKey: string,
    ): string {

        const validity = {start: validityStart, end: validityEnd};

        const pubKey = serialization.deserializePublicKey(subjectPublicKey);
        const privKey = serialization.dezerializePrivateKey(issuerPrivateKey);

        const signedData = canocializeSignedData(this.VERSION, subjectName, pubKey, validity);
        const signature = this.crypto.sign(signedData, privKey);

        const certificate = {
            version: this.VERSION,
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
    ) : boolean {

        const sign = serialization.deserializeSignature(signature);
        const cert = serialization.deserializeCertificate(certificate);
        const pubKey = serialization.deserializePublicKey(caPublicKey);

        // if the now is not within the validity of the certificate we directly return false
        var now = this.now();
        if(now < cert.validity.start || now > cert.validity.end)
            return false;

        // Calculate the public key which verifies the signature
        const publicKey = this.crypto.recoverPublicKey(message, sign);

        // Reassmble the certificate data
        const signedData = canocializeSignedData(cert.version, subjectName, publicKey, cert.validity);
        const isvalid = this.crypto.verify(signedData, cert.signature, pubKey);
        return isvalid;
    }

    public dateToUnixTime(date:Date):number{

        return Math.floor(date.getTime() / 1000);
    }

    public now() : number{

        return this.dateToUnixTime(new Date());
    };
    
    public plus(timstamp, years, months, days, hours, minutes, seconds)
    {
        var date = new Date(timstamp * 1000);
        
        date.setFullYear(date.getFullYear() + years);
        date.setMonth(date.getMonth() + months);
        date.setDate(date.getDate() + days);
        date.setHours(date.getHours() + hours);
        date.setMinutes(date.getMinutes() + minutes);
        date.setSeconds(date.getSeconds() + seconds);
    
        return this.dateToUnixTime(date); 
    }
}

function canocializeSignedData(
    version: number,
    subjectName: string,
    subjectPublicKey: crypto.PublicKey,
    validity: TimePeroid) {

    return version + "+" + subjectName + "+" + subjectPublicKey.hash + "+" + validity.start + "+" + validity.end;
}
