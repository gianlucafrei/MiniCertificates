import{ALL} from '../src/suites';
import{MC} from '../src/main';

/*
    This script prints a simple report of the key and certificate sizes
    for different cipher suites.
*/


console.log("Suite   Secret Key   Public Key   Certificate")

ALL.forEach(suite => {

    const mc = new MC(suite.name);

    // Step 1: Key generation for ca and user
    const caPrivate = mc.newPrivateKey();

    const userPrivate = mc.newPrivateKey();
    const userPublic = mc.computePublicKeyFromPrivateKey(userPrivate);

    // Step 2: Ca signs a certificate for the user 
    const certificate = mc.signCertificate("user", userPublic, {start: 1_550_741_071, end: 1_550_999_999}, caPrivate);

    const privateKeySize = userPrivate.length / 2; // always two chars per byte
    const publicKeySize = userPublic.length / 2;
    const certificateSize = certificate.length / 2;

    console.log('%s      %d         %d           %d', suite.name, privateKeySize, publicKeySize, certificateSize);
});


