import {MC} from '../src/main';
import {P192SHA256} from '../src/suites';


describe('interface test', ()=>{

    test('test valid suites', ()=>{

        //those cypher suites exists
        const mc1 = new MC('p192');
        expect(mc1).not.toBeNull();

        const mc2 = new MC('p256');
        expect(mc2).not.toBeNull();

        // This does not
        expect(()=>new MC('does not exists')).toThrow();
    });

});

describe('certificate test', ()=>{

    const mc = new MC(P192SHA256);

    // Step 1: Key generation for ca and user
    const caPrivate = mc.newPrivateKey();
    const caPublic = mc.computePublicKeyFromPrivateKey(caPrivate);

    const userPrivate = mc.newPrivateKey();
    const userPublic = mc.computePublicKeyFromPrivateKey(userPrivate);

    // Step 2: Ca signs a certificate for the user 
    const certificate = mc.signCertificate("user", userPublic, {start: 444, end: 888}, caPrivate);

    // Steps 3: User authenticates himself with the certificate by signing a nonce
    const nonce = "this is a nonce as a string"
    const signature = mc.sign(nonce, userPrivate);

    test('test certificate validation correct', ()=>{

        // Step 4: Check authentication
        const isAuthentic = mc.verifySignature("user", nonce, signature, certificate, caPublic);
        expect(isAuthentic).toBe(true);
    });

    test('test certificate validation invalid user', ()=>{

        // Step 4: Check authentication
        const isAuthentic = mc.verifySignature("userX", nonce, signature, certificate, caPublic);
        expect(isAuthentic).toBe(false);
    });

    test('test certificate validation invalid message', ()=>{

        // Step 4: Check authentication
        const isAuthentic = mc.verifySignature("user", "this is another nonce", signature, certificate, caPublic);
        expect(isAuthentic).toBe(false);
    });

    test('test certificate validation invalid ca', ()=>{

        const ca2Private = mc.newPrivateKey();
        const ca2Public = mc.computePublicKeyFromPrivateKey(ca2Private);

        // Step 4: Check authentication
        const isAuthentic = mc.verifySignature("user", nonce, signature, certificate, ca2Public);
        expect(isAuthentic).toBe(false);
    });

});
