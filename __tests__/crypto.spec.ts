import * as crypto from '../src/crypto';
import * as suites from '../src/suites';

describe('crypto test', ()=>{

    let allSuites = [suites.P192SHA256, suites.P256SHA256];

    allSuites.forEach(suite => {
        
        let cr = new crypto.Crypto(suite);

        test('test key recovery', ()=>{

            const privateKey = cr.privateKeyFromSecret('aa');
            const publicKey = cr.publicFromPrivate(privateKey);
    
            const message = "blablabla";
            const signature = cr.sign(message, privateKey);
    
            const recoveredKey = cr.recoverPublicKey(message, signature);
            expect(recoveredKey).toEqual(publicKey);
        });
    
        test('test validation correct signature', ()=>{
    
            const privateKey = cr.generatePrivateKey();
            const publicKey = cr.publicFromPrivate(privateKey);
    
            const message = "foobar";
            const signature = cr.sign(message, privateKey);
    
            const isValid = cr.verify(message, signature, publicKey);
    
            expect(isValid).toBe(true);
        })
    
        test('test validation incorrect signature', ()=>{
    
            const privateKey = cr.generatePrivateKey();
            const publicKey = cr.publicFromPrivate(privateKey);
    
            const signature = cr.sign("foobar", privateKey);
            const isValid = cr.verify("notfoobar", signature, publicKey);
    
            expect(isValid).toBe(false);
    
        });
    });
  })