import * as minicert from '../src/main';
import * as serialization from '../src/serialization'

describe('certificate test', ()=>{

    // Step 1: Key generation for ca and user
    const caPrivate = minicert.newPrivateKey();

    const userPrivate = minicert.newPrivateKey();
    const userPublic = minicert.computePublicKeyFromPrivateKey(userPrivate);

    // Step 2: Ca signs a certificate for the user 
    const certificate = minicert.signCertificate("user", userPublic, {start: 444, end: 888}, caPrivate);

    test('test serialization', ()=>{

        const data = serialization.serializeCertificate(certificate);
        expect(data).not.toBeNull();
    });

})
