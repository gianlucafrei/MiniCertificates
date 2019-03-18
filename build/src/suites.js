"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const Hashes = require('jshashes');
const EC = require("elliptic").ec;
exports.P192SHA256 = {
    name: 'p192',
    ec: new EC('p192'),
    curvelenght: 192,
    hashfunction: new Hashes.SHA256
};
exports.P256SHA256 = {
    name: 'p256',
    ec: new EC('p256'),
    curvelenght: 256,
    hashfunction: new Hashes.SHA256
};
exports.ALL = [exports.P192SHA256, exports.P256SHA256];
//# sourceMappingURL=suites.js.map