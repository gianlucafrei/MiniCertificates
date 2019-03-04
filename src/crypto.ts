import {Suite} from './suites'
const BN = require('bn.js');

/**
 * This module provides an simpler interface for the elliptic library.
 * In case you would like to use another crypto back-end you could write
 * another Crypto Class. (For using Openssl or similar...)
 */

export interface PrivateKey{
    /* Private exponent */
    x: string
}

export interface PublicKey{
    /* As public key we use the hash point on the curve*/
    hash: string
}

export interface Signature{
    /* r,s are the two parts of an ecdsa signature.
       j is the public key recovery value */
    r: string,
    s: string,
    j: number
}

export class Crypto{

    suite: Suite;

    constructor(suite:Suite){
        this.suite = suite;
    }


    public privateKeyFromSecret(secret:string) : PrivateKey{

        const keyPair = this.suite.ec.keyPair({priv: secret});
        const exponent = keyPair.getPrivate('hex');
        return {x:exponent};
    };
    
    public generatePrivateKey() : PrivateKey{
    
        const key = this.suite.ec.genKeyPair();
        const exponent = key.getPrivate('hex');
        
        return {x:exponent};
    }
    
    public publicFromPrivate(privateKey: PrivateKey) : PublicKey{
    
        const keyPair = this.suite.ec.keyPair({priv: privateKey.x});
        const pubPointAsString = this.canonizeCurvePoint(keyPair.getPublic())
        const hash = this.hashMessage(pubPointAsString);
        return {hash: hash}
    }
    
    public sign(message: string, privateKey: PrivateKey) : Signature{
    
        const digest = this.hashMessage(message);
        const key = this.suite.ec.keyPair({priv: privateKey.x});
        const signature = key.sign(digest);
    
        return {
            r: signature.r.toString(16),
            s: signature.s.toString(16),
            j: signature.recoveryParam
        }
    }
    
    public recoverPublicKey(message: string, signature: Signature) : PublicKey{
    
        const digest = this.hashMessage(message);
    
        // This is a due to a bug of the elliptic library
        var digestBase10 = (new BN(digest, 16)).toString()
    
        var recoveredPoint =  this.suite.ec.recoverPubKey(digestBase10, signature, signature.j, 'object');
        var pointAsString = this.canonizeCurvePoint(recoveredPoint);
    
        const hash = this.hashMessage(pointAsString);
        return {hash: hash}
    }
    
    public verify(message:string, signature:Signature, publicKey:PublicKey){
        
        const recoveredPubkey = this.recoverPublicKey(message, signature);
        return publicKey.hash == recoveredPubkey.hash;
    }
    
    private canonizeCurvePoint(point){
    
        return point.x.toString(16) + ":" + point.y.toString(16);
    }
    
    private hashMessage(message:string) : string{
    
        const digest = this.suite.hashfunction.hex(message);

        /*
        Trim the digest to the curve size
        Example:
        Digest is 256 bit => 32 Bytes => 64 hex chars
        Curve is 192 bit =>  24 Bytes => 48 hex chars
        */
        return digest.substring(0, this.suite.curvelenght/4);
    }

}



