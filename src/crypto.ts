import { Suite } from './suites'
const BN = require('bn.js');

/**
 * This module provides an simpler interface for the elliptic library.
 * In case you would like to use another crypto back-end you could write
 * another Crypto Class. (For using Openssl or similar...)
 */

/**
 * A private key exists of only a secret scalar.
 */
export interface PrivateKey {
    /* Private exponent */
    x: string
}

/**
 * As public key the hash of the public curve point is used.
 * The hash is used because it is only half in size compared to the curve point.
 */
export interface PublicKey {
    /* As public key we use the hash point on the curve*/
    hash: string
}

/**
 * A signature consists of r, s which are numbers encoded as hexstrings and
 * the recovery parameter 0<=j<4 which is a integer.
 */
export interface Signature {
    /* r,s are the two parts of an ecdsa signature.
       j is the public key recovery value */
    r: string,
    s: string,
    j: number
}

/**
 * The crypto class is essentially just a wrapper around the elliptic.js library.
 * It provides a consistent interface for the main.js file which uses this class to
 * generate certificates and signatures.
 */
export class Crypto {

    /**
     * The used suite as object
     */
    suite: Suite;

    /**
     * The random function used to create new keys
     */
    readonly random: (number) => number[];

    /**
     * Creates a new instance of this class.
     * @param suite The suite as one of the objects of the suites.ts file
     * @param randomFunction The random function callback
     */
    constructor(suite: Suite, randomFunction: (number) => number[]) {
        this.suite = suite;
        this.suite.ec.rand = randomFunction;
        this.random = randomFunction;
    };

    /**
     * Generates a new private key and returns it
     */
    public generatePrivateKey(): PrivateKey {

        const entropy = this.random(this.suite.curvelenght);
        const key = this.suite.ec.genKeyPair({ entropy: entropy });
        const exponent = key.getPrivate('hex');

        return { x: exponent };
    }

    /**
     * Returns a private key object with the secret as exponent.
     * @param secret The private exponent as hexstring
     */
    public privateKeyFromSecret(secret: string): PrivateKey {

        const keyPair = this.suite.ec.keyPair({ priv: secret });
        const exponent = keyPair.getPrivate('hex');
        return { x: exponent };
    };

    /**
     * Given a private key this function computes the corresponding public key.
     * @param privateKey The private key generated with generatePrivateKey()
     */
    public publicFromPrivate(privateKey: PrivateKey): PublicKey {

        const keyPair = this.suite.ec.keyPair({ priv: privateKey.x });
        const pubPointAsString = this.canonizeCurvePoint(keyPair.getPublic())
        const hash = this.hashMessage(pubPointAsString);
        return { hash: hash }
    }

    /**
     * Hashes a given message and signs the resulting hash.
     * @param message The message as sting
     * @param privateKey The private key instance
     */
    public sign(message: string, privateKey: PrivateKey): Signature {

        const digest = this.hashMessage(message);
        const key = this.suite.ec.keyPair({ priv: privateKey.x });
        const signature = key.sign(digest);

        return {
            r: signature.r.toString(16),
            s: signature.s.toString(16),
            j: signature.recoveryParam
        }
    }

    /**
     * Recovers a public key which is valid for the given signature and message
     * @param message 
     * @param signature 
     */
    public recoverPublicKey(message: string, signature: Signature): PublicKey {

        const digest = this.hashMessage(message);

        // This is a due to a bug of the elliptic library
        var digestBase10 = (new BN(digest, 16)).toString()

        var recoveredPoint = this.suite.ec.recoverPubKey(digestBase10, signature, signature.j, 'object');
        var pointAsString = this.canonizeCurvePoint(recoveredPoint);

        const hash = this.hashMessage(pointAsString);
        return { hash: hash }
    }

    /**
     * Returns true when the given signature is valid for the given message and public key.
     * @param message 
     * @param signature 
     * @param publicKey 
     */
    public verify(message: string, signature: Signature, publicKey: PublicKey) {

        const recoveredPubkey = this.recoverPublicKey(message, signature);
        return publicKey.hash == recoveredPubkey.hash;
    }

    /**
     * Maps a curve point to a string which can be hashed
     * @param point 
     */
    private canonizeCurvePoint(point) {

        return point.x.toString(16) + ":" + point.y.toString(16);
    }

    /**
     * Hashes a string and trims the resulting hash to the length of the curve
     * @param message 
     */
    private hashMessage(message: string): string {

        const digest = this.suite.hashfunction.hex(message);

        /*
        Trim the digest to the curve size
        Example:
        Digest is 256 bit => 32 Bytes => 64 hex chars
        Curve is 192 bit =>  24 Bytes => 48 hex chars
        */
        return digest.substring(0, this.suite.curvelenght / 4);
    }
}
