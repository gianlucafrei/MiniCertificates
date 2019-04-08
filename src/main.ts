import * as crypto from "./crypto";
import * as suites from './suites';
import * as serialization from './serialization';

interface TimePeriod {
    /* Time periods consists of two 32bit integers in unix time*/
    start: number,
    end: number
}

export interface Certificate {
    version: number,
    subject: string,
    validity: TimePeriod,
    signature: crypto.Signature
}

/**
 * This is the only object a caller of this library should interact with.
 * All methods have no side effects.
 * 
 * Create a new object by calling const mc = new MC('p256');
 * All function parameters are strings.
 * All return values are hexadecimal numbers as strings.
 * 
 */
export class MC {

    public readonly VERSION = 0;
    readonly suite: suites.Suite;
    readonly crypto: crypto.Crypto;

    constructor(cryptoSuite: string, randomFunction: (number)=>number[]) {

        switch (cryptoSuite) {
            case 'p192':
                this.suite = suites.P192SHA256;
                break;
            case 'p256':
                this.suite = suites.P256SHA256;
                break;
            default:
                throw new Error('unknown cypher suite');
        }

        this.crypto = new crypto.Crypto(this.suite, randomFunction);
    };

    /**
     *  Creates a new private key.
     */
    public newPrivateKey(): string {

        const key = this.crypto.generatePrivateKey();
        return serialization.serializePrivateKey(key);
    }

    /**
     * Computes the corresponding public key of a private key.
     * @param privateKey The private key. (Usually generated with newPrivateKey())
     */
    public computePublicKeyFromPrivateKey(privateKey: string): string {

        const privKey = serialization.deserializePrivateKey(privateKey);
        const pubKey = this.crypto.publicFromPrivate(privKey);
        return serialization.serializePublicKey(pubKey);

    }

    /**
     * Signs a public key certificate with a private key
     * @param subjectName The name of the holder of the public key
     * @param subjectPublicKey The public key
     * @param validityStart The start time of the validity as unix timestamp
     * @param validityEnd  The end time of the validity as unix timestamp
     * @param issuerPrivateKey The private key to sign the certificate
     */
    public signCertificate(
        subjectName: string, 
        subjectPublicKey: string,
        validityStart: number,
        validityEnd: number,
        issuerPrivateKey: string,
    ): string {

        const validity = {start: validityStart, end: validityEnd};

        const pubKey = serialization.deserializePublicKey(subjectPublicKey);
        const privKey = serialization.deserializePrivateKey(issuerPrivateKey);

        const signedData = canonicalizeCertificateData(this.VERSION, subjectName, pubKey, validity);
        const signature = this.crypto.sign(signedData, privKey);

        const certificate = {
            version: this.VERSION,
            subject: subjectName,
            validity: validity,
            signature: signature
        }

        return serialization.serializeCertificate(certificate);
    }

    /**
     * Signs a message with a private key
     * Returns only the signature, not the message itself
     * @param message The message to sign as string
     * @param privateKey The private key to sign the message
     */
    public sign(message: string, privateKey: string): string {

        const privKey = serialization.deserializePrivateKey(privateKey);
        const signature = this.crypto.sign(message, privKey);
        return serialization.serializeSignature(signature);
    }

    /**
     * Returns the public key of the signer
     * @param message The signed message
     * @param signature The signature for the message
     */
    public recoverSignerPublicKey(message:string, signature:string){

        const sign = serialization.deserializeSignature(signature);
        const pk = this.crypto.recoverPublicKey(message, sign);
        
        return serialization.serializePublicKey(pk);

    }

    public verifySignatureWithPublicKey(message:string, signature:string, publicKey:string){

        const sign = serialization.deserializeSignature(signature);
        const pk = serialization.deserializePublicKey(publicKey);

        return this.crypto.verify(message, sign, pk);
    }

    /**
     * Verifies the signature of a given message with a certificate.
     * @param subjectName The expected name of the signer.
     * @param message The signed message
     * @param signature The signature of the message
     * @param certificate The public key certificate of the signer
     * @param trustedCaPublicKeys The public key of the ca who signed the message
     */
    public verifySignatureWithCertificate(
        subjectName: string,
        message: string,
        signature: string,
        certificate: string,
        trustedCaPublicKeys: string[]
    ) : boolean {

        const sign = serialization.deserializeSignature(signature);
        const cert = serialization.deserializeCertificate(certificate);

        // if the now is not within the validity of the certificate we directly return false
        var now = this.now();
        if(now < cert.validity.start || now > cert.validity.end)
            return false;

        // Calculate the public key which verifies the signature
        const publicKey = this.crypto.recoverPublicKey(message, sign);

        // Reassemble the certificate data
        const certificateSignedData = canonicalizeCertificateData(cert.version, subjectName, publicKey, cert.validity);
        const validPublicKeyForCertificate = serialization.serializePublicKey(this.crypto.recoverPublicKey(certificateSignedData, cert.signature));

        const isValid = (trustedCaPublicKeys.indexOf(validPublicKeyForCertificate) > -1);
        return isValid;
    }

    /**
     * Returns the name of the signer is the signature matches the certificate
     * or null if the signature is not valid for the certificate
     * @param message The signed message
     * @param signature The signature of the message
     * @param certificate The public key certificate of the signer
     * @param trustedCaPublicKeys The public key of the ca who signed the message
     */
    public getAuthenticSigner(
        message: string,
        signature: string,
        certificate: string,
        trustedCaPublicKeys: string[]
    ){

        var claimedName = this.getUsernameOfCertificate(certificate);
        var isValid = this.verifySignatureWithCertificate(claimedName, message, signature, certificate, trustedCaPublicKeys);
        if(isValid)
            return claimedName;
        else
            return null;
    }

    public getUsernameOfCertificate(certificate: string){

        var cert = serialization.deserializeCertificate(certificate);
        return cert.subject;
    }

    /**
     * Converts a javascript date to a unix timestamp
     * @param date The date to convert
     */
    public dateToUnixTime(date:Date):number{

        return Math.floor(date.getTime() / 1000);
    }

    /**
     * Returns the current time as unix timestamp.
     */
    public now() : number{

        return this.dateToUnixTime(new Date());
    };
    
    /**
     * Adds a time period to a unix timestamp
     * @param timestamp The unix timestamp to add the time period to
     * @param years Number of years to add
     * @param months Number of months to add
     * @param days Number of days to add
     * @param hours Number of hours to add
     * @param minutes Number of minutes to add
     * @param seconds Number seconds to add
     */
    public plus(timestamp, years=0, months=0, days=0, hours=0, minutes=0, seconds=0)
    {
        var date = new Date(timestamp * 1000);
        
        date.setFullYear(date.getFullYear() + years);
        date.setMonth(date.getMonth() + months);
        date.setDate(date.getDate() + days);
        date.setHours(date.getHours() + hours);
        date.setMinutes(date.getMinutes() + minutes);
        date.setSeconds(date.getSeconds() + seconds);
    
        return this.dateToUnixTime(date); 
    }

    /**
     * WARNING: This is not secure
     * Generates n random bytes 
     * @param n 
     */
    public static insecureRandom(n){

        return Array.from({length: n}, () => Math.floor(Math.random() * 256));

    }
}

/**
 * Converts the inputs to a string which will be signed
 * @param version The version of the library
 * @param subjectName The name of the certificate subject
 * @param subjectPublicKey The public key of the subject
 * @param validity The validity of the certificate
 */
function canonicalizeCertificateData(
    version: number,
    subjectName: string,
    subjectPublicKey: crypto.PublicKey,
    validity: TimePeriod) {

    return version + "+" + subjectName + "+" + subjectPublicKey.hash + "+" + validity.start + "+" + validity.end;
}


module.exports = MC;