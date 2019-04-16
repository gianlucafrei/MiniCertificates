const Hashes = require('jshashes');
const EC = require("elliptic").ec;

/**
 * A suite consists of a name, a elliptic curve and a hashfunction.
 */
export interface Suite {
    name: string,
    ec,
    curvelenght: number,
    hashfunction
}

/**
 * The NIST P-192 curve with SHA256 as hash function
 */
export const P192SHA256: Suite = {

    name: 'p192',
    ec: new EC('p192'),
    curvelenght: 192,
    hashfunction: new Hashes.SHA256
}

/**
 * The NIST P-256 curve with SHA256 as hash function
 */
export const P256SHA256: Suite = {
    name: 'p256',
    ec: new EC('p256'),
    curvelenght: 256,
    hashfunction: new Hashes.SHA256
}

/**
 * All supported curves as an array, used for testing
 */
export const ALL = [P192SHA256, P256SHA256];