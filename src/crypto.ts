const EC = require("elliptic").ec;
const BN = require('bn.js');
const Hashes = require('jshashes');

const ec = new EC('p192');
const SHA256 =  new Hashes.SHA256
const CURVE_LENGHT=192;

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

export function privateKeyFromSecret(secret:string) : PrivateKey{

    const keyPair = ec.keyPair({priv: secret});
    const exponent = keyPair.getPrivate('hex');
    return {x:exponent};
}

export function generatePrivateKey() : PrivateKey{

    const key = ec.genKeyPair();
    const exponent = key.getPrivate('hex');
    
    return {x:exponent};
}

export function publicFromPrivate(privateKey : PrivateKey) : PublicKey{

    const keyPair = ec.keyPair({priv: privateKey.x});
    const pubPointAsString = canonizeCurvePoint(keyPair.getPublic())
    const hash = hashMessage(pubPointAsString);
    return {hash: hash}
}

export function sign(message: string, privateKey : PrivateKey) : Signature{

    const digest = hashMessage(message);
    const key = ec.keyPair({priv: privateKey.x});
    const signature = key.sign(digest);

    return {
        r: signature.r.toString(16),
        s: signature.s.toString(16),
        j: signature.recoveryParam
    }
}

export function recoverPublicKey(message: string, signature : Signature) : PublicKey{

    const digest = hashMessage(message);

    // This is a due to a bug of the elliptic library
    var digestBase10 = (new BN(digest, 16)).toString()

    var recoveredPoint =  ec.recoverPubKey(digestBase10, signature, signature.j, 'object');
    var pointAsString = canonizeCurvePoint(recoveredPoint);

    const hash = hashMessage(pointAsString);
    return {hash: hash}
}

export function verify(message:string, signature:Signature, publicKey:PublicKey){
    
    const recoveredPubkey = recoverPublicKey(message, signature);
    return publicKey.hash == recoveredPubkey.hash;
}

function canonizeCurvePoint(point){

    return point.x.toString(16) + ":" + point.y.toString(16);
}

function hashMessage(message:string) : string{

    const digest = SHA256.hex(message);
    return digest.substring(0, CURVE_LENGHT/4);
}