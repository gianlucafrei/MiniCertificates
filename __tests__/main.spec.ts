import * as minicert from '../src/main';

describe('certificate test', ()=>{

    // Step 1: Key generation for ca and user
    const caPrivate = minicert.newPrivateKey();
    const caPublic = minicert.computePublicKeyFromPrivateKey(caPrivate);

    const userPrivate = minicert.newPrivateKey();
    const userPublic = minicert.computePublicKeyFromPrivateKey(userPrivate);

    // Step 2: Ca signs a certificate for the user 
    const certificate = minicert.signCertificate("user", userPublic, {start: 444, end: 888}, caPrivate);

    // Steps 3: User authenticates himself with the certificate by signing a nonce
    const nonce = "this is a nonce as a string"
    const signature = minicert.sign(nonce, userPrivate);

    test('test certificate validation correct', ()=>{

        // Step 4: Check authentication
        const isAuthentic = minicert.verifySignature("user", nonce, signature, certificate, caPublic);
        expect(isAuthentic).toBe(true);
    });

    test('test certificate validation invalid user', ()=>{

        // Step 4: Check authentication
        const isAuthentic = minicert.verifySignature("userX", nonce, signature, certificate, caPublic);
        expect(isAuthentic).toBe(false);
    });

    test('test certificate validation invalid message', ()=>{

        // Step 4: Check authentication
        const isAuthentic = minicert.verifySignature("user", "this is another nonce", signature, certificate, caPublic);
        expect(isAuthentic).toBe(false);
    });

    test('test certificate validation invalid ca', ()=>{

        const ca2Private = minicert.newPrivateKey();
        const ca2Public = minicert.computePublicKeyFromPrivateKey(ca2Private);

        // Step 4: Check authentication
        const isAuthentic = minicert.verifySignature("user", nonce, signature, certificate, ca2Public);
        expect(isAuthentic).toBe(false);
    });

})
