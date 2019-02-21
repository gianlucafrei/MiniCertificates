const Hashes = require('jshashes');
const EC = require("elliptic").ec;

export interface Suite {
    name: string,
    ec,
    curvelenght: number,
    hashfunction
}

export const P192SHA256:Suite = {

    name: 'p192',
    ec: new EC('p192'),
    curvelenght: 192,
    hashfunction: new Hashes.SHA256
}

export const P256SHA256:Suite={
    name: 'p256',
    ec: new EC('p256'),
    curvelenght: 256,
    hashfunction: new Hashes.SHA256
}

export const ALL = [P192SHA256, P256SHA256];