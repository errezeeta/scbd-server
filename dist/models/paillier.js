"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PaillierSys = void 0;
class PaillierSys {
    constructor(pubk, privk) {
        this.publicKey = pubk;
        this.privateKey = privk;
        this.count = this.publicKey.encrypt(0n);
        this.counter = "0";
    }
}
exports.PaillierSys = PaillierSys;
exports.default = PaillierSys;
//# sourceMappingURL=paillier.js.map