describe('certificate test', ()=>{

    const minicert = require("../src/main");
    const mc = new minicert('p256', minicert.insecureRandom);


    // Step 1: Key generation for ca and user
    const caPrivate = mc.newPrivateKey();

    const userPrivate = mc.newPrivateKey();
    const userPublic = mc.computePublicKeyFromPrivateKey(userPrivate);

    // Step 2: Ca signs a certificate for the user 
    const validityStart = mc.now();
    const validEnd = mc.plus(validityStart, 0, 2, 0, 0, 0,0);
    const certificate = mc.signCertificate("user", userPublic, validityStart, validEnd, caPrivate);

    const sign = mc.sign("foobar", userPrivate);

    test('test certificate size', ()=>{

        // Since the certificate is serialized as a hex string the length
        // is just the length of the string diveded by two
        const size = certificate.length / 2;
        expect(size).toBeLessThanOrEqual(100);

    });

    test('test signature size', ()=>{

        const signSize = sign.length / 2;
        expect(signSize).toBeLessThanOrEqual(90);

    })
})
