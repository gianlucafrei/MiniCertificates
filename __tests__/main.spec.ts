import {MC} from '../src/main';


const mc = new MC('p256');

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

    // Step 1: Key generation for ca and user
    const caPrivate = mc.newPrivateKey();
    const caPublic = mc.computePublicKeyFromPrivateKey(caPrivate);

    const userPrivate = mc.newPrivateKey();
    const userPublic = mc.computePublicKeyFromPrivateKey(userPrivate);

    // Step 2: Ca signs a certificate for the user 
    const validityStart = mc.now();
    const validEnd = mc.plus(validityStart, 0, 2, 0, 0, 0,0);
    const certificate = mc.signCertificate("user", userPublic, validityStart, validEnd, caPrivate);

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

    test('test invalid validity', ()=>{

        const validityStart = mc.plus(mc.now(), -1, 0, 0, 0, 0, 0);
        const validEnd = mc.plus(validityStart, 0, 2, 0, 0, 0,0);
        const certificate = mc.signCertificate("user", userPublic, validityStart, validEnd, caPrivate);

        const isAuthentic = mc.verifySignature("user", nonce, signature, certificate, caPublic);
        expect(isAuthentic).toBe(false);

    });

});

describe('timestamps test', ()=>{

    test('test timestamp plus', ()=>{

        // Test if we add 0
        const now = mc.now();
        const alsoNow = mc.plus(now, 0,0,0,0,0,0);
        expect(alsoNow).toBe(now);

        const inOneHour = mc.plus(now, 0,0,0, 1,0,0);
        expect(inOneHour).toBe(now + 3600);

    });

});
