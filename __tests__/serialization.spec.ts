import {MC} from '../src/main';

describe('certificate test', ()=>{


    const mc = new MC('p192');

    // Step 1: Key generation for ca and user
    const caPrivate = mc.newPrivateKey();

    const userPrivate = mc.newPrivateKey();
    const userPublic = mc.computePublicKeyFromPrivateKey(userPrivate);

    // Step 2: Ca signs a certificate for the user 
    const certificate = mc.signCertificate("user", userPublic, {start: 444, end: 888}, caPrivate);

    test('test certificate size', ()=>{

        // Since the certificate is serialized as a hex string the length
        // is just the length of the string diveded by two
        const size = certificate.length / 2;
        expect(size).toBeLessThanOrEqual(100);

    });
})
