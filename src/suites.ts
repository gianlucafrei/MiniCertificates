const Hashes = require('jshashes');
const EC = require("elliptic").ec;

export interface Suite {
    ec,
    curvelenght: number,
    hashfunction
}

export const P192SHA256:Suite = {

    ec: new EC('p192'),
    curvelenght: 192,
    hashfunction: new Hashes.SHA256
}

export const P256SHA256:Suite={
    ec: new EC('p256'),
    curvelenght: 256,
    hashfunction: new Hashes.SHA256
}