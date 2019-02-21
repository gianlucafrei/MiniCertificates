import {MC} from '../src/main';
import * as serialization from '../src/serialization'

describe('certificate test', ()=>{


    const mc = new MC('p192');

    // Step 1: Key generation for ca and user
    const caPrivate = mc.newPrivateKey();

    const userPrivate = mc.newPrivateKey();
    const userPublic = mc.computePublicKeyFromPrivateKey(userPrivate);

    // Step 2: Ca signs a certificate for the user 
    const certificate = mc.signCertificate("user", userPublic, {start: 444, end: 888}, caPrivate);

    test('test serialization', ()=>{

        const data = serialization.serializeCertificate(certificate);
        
        const size = data.length;
        expect(size).toBeLessThanOrEqual(100);
        
        const unpacked = serialization.deserializeCertificate(data);

        expect(unpacked).toEqual(certificate);
    });

})
