"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PaillierSys = void 0;
class PaillierSys {
    constructor(pubk, privk) {
        this.publicKey = pubk;
        this.privateKey = privk;
        this.count = this.publicKey.encrypt(0n);
        this.counter = ["0", "0"];
    }
    getResoults() {
        var res = [0, 0];
        res[0] = Number(this.counter[0]) / 1000;
        res[1] = Number(this.counter[1]);
        return res;
    }
}
exports.PaillierSys = PaillierSys;
exports.default = PaillierSys;
//# sourceMappingURL=paillier.js.map