const minicert = require("../src/main");
const mc = new minicert('p256', minicert.insecureRandom);

describe('interface test', ()=>{

    test('test valid suites', ()=>{

        //those cypher suites exists
        const mc1 = new minicert('p192');
        expect(mc1).not.toBeNull();

        const mc2 = new minicert('p256');
        expect(mc2).not.toBeNull();

        // This does not
        expect(()=>new minicert('does not exists')).toThrow();
    });

});

describe("randomness test", ()=>{

    test("test that two new keys are not equal", ()=>{

        const key1 = mc.newPrivateKey();
        const key2 = mc.newPrivateKey();
        
        expect(key1).not.toEqual(key2);
    });
})

describe('certificate test', ()=>{

    // Step 1: Key generation for ca and user
    const caPrivate = mc.newPrivateKey();
    const caPublic = mc.computePublicKeyFromPrivateKey(caPrivate);

    const otherCaPublic = mc.computePublicKeyFromPrivateKey(mc.newPrivateKey());

    const trustedKeys = [otherCaPublic, caPublic];

    const userPrivate = mc.newPrivateKey();
    const userPublic = mc.computePublicKeyFromPrivateKey(userPrivate);

    // Step 2: Ca signs a certificate for the user 
    const validityStart = mc.now();
    const validEnd = mc.plus(validityStart, 0, 2, 0, 0, 0,0);
    const certificate = mc.signCertificate("user", userPublic, validityStart, validEnd, caPrivate);

    // Steps 3: User authenticates himself with the certificate by signing a nonce
    const nonce = "this is a nonce as a string"
    const signature = mc.sign(nonce, userPrivate);

    test('test verify with valid public key', ()=>{

        const isAuthentic = mc.verifySignatureWithPublicKey(nonce, signature, userPublic);
        expect(isAuthentic).toBe(true);

    });

    test('test verify with invalid public key', ()=>{

        const isAuthentic = mc.verifySignatureWithPublicKey(nonce, signature, caPublic);
        expect(isAuthentic).toBe(false);

    });

    test('test public key recover', ()=>{

        const recoveredPk = mc.recoverSignerPublicKey(nonce, signature);
        expect(recoveredPk).toEqual(userPublic);

    })

    test('test certificate validation correct', ()=>{

        // Step 4: Check authentication
        const isAuthentic = mc.verifySignatureWithCertificate("user", nonce, signature, certificate, trustedKeys);
        expect(isAuthentic).toBe(true);
    });

    test('test getAuthenticSigner', ()=>{

        const signer = mc.getAuthenticSigner(nonce, signature, certificate, trustedKeys);
        expect(signer).toBe("user");

        const invalidSigner = mc.getAuthenticSigner("anothernonce", signature, certificate, trustedKeys);
        expect(invalidSigner).toBeNull();
        
    });

    test('test certificate validation invalid user', ()=>{

        // Step 4: Check authentication
        const isAuthentic = mc.verifySignatureWithCertificate("userX", nonce, signature, certificate, trustedKeys);
        expect(isAuthentic).toBe(false);
    });

    test('test certificate validation invalid message', ()=>{

        // Step 4: Check authentication
        const isAuthentic = mc.verifySignatureWithCertificate("user", "this is another nonce", signature, certificate, trustedKeys);
        expect(isAuthentic).toBe(false);
    });

    test('test certificate validation invalid ca', ()=>{

        const ca2Private = mc.newPrivateKey();
        const ca2Public = mc.computePublicKeyFromPrivateKey(ca2Private);

        // Step 4: Check authentication
        const isAuthentic = mc.verifySignatureWithCertificate("user", nonce, signature, certificate, [ca2Public]);
        expect(isAuthentic).toBe(false);
    });

    test('test invalid validity', ()=>{

        const validityStart = mc.plus(mc.now(), -1, 0, 0, 0, 0, 0);
        const validEnd = mc.plus(validityStart, 0, 2, 0, 0, 0,0);
        const certificate = mc.signCertificate("user", userPublic, validityStart, validEnd, caPrivate);

        const isAuthentic = mc.verifySignatureWithCertificate("user", nonce, signature, certificate, trustedKeys);
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
