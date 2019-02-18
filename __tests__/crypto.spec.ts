import {privateKeyFromSecret, publicFromPrivate, sign, recoverPublicKey, generatePrivateKey, verify} from '../src/crypto';

const EC = require("elliptic").ec;
const BN = require('bn.js');

const ec = new EC('p192');

describe('test elliptic', ()=>{

    test('testrecovery2', ()=>{
        //var key = ec.genKeyPair();
        var secret = "aa"
        var key = ec.keyPair({priv: secret});

        // Get public key
        var pubPoint = key.getPublic();

        // Sign the message's hash (input must be an array, or a hex-string)
        var msgHash = '492f3f38d6b5d3ca859514e250e25ba65935bcdd9f4f40c1';
        var signature = key.sign(msgHash, 'object');

        var hashBase10 = (new BN(msgHash, 16)).toString()
        var r =  ec.recoverPubKey(hashBase10, signature, signature.recoveryParam, 'object');

        expect(r.x.toString(16)).toEqual(pubPoint.x.toString(16));
    })
})

describe('crypto test', ()=>{    
    test('test key recovery', ()=>{

        const privateKey = privateKeyFromSecret('aa');
        const publicKey = publicFromPrivate(privateKey);

        const message = "blablabla";
        const signature = sign(message, privateKey);

        const recoveredKey = recoverPublicKey(message, signature);
        expect(recoveredKey).toEqual(publicKey);
    });

    test('test validation correct signature', ()=>{

        const privateKey = generatePrivateKey();
        const publicKey = publicFromPrivate(privateKey);

        const message = "foobar";
        const signature = sign(message, privateKey);

        const isValid = verify(message, signature, publicKey);

        expect(isValid).toBe(true);
    })

    test('test validation incorrect signature', ()=>{

        const privateKey = generatePrivateKey();
        const publicKey = publicFromPrivate(privateKey);

        const signature = sign("foobar", privateKey);
        const isValid = verify("notfoobar", signature, publicKey);

        expect(isValid).toBe(false);

    });
  })