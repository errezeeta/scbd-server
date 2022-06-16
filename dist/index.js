"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.paillierSys = exports.pubk_ce = exports.keys = void 0;
const app_1 = __importDefault(require("./app"));
const rsa_1 = require("@scbd/rsa");
const node_fetch_1 = __importDefault(require("node-fetch"));
const paillier_1 = __importDefault(require("./models/paillier"));
const bic = __importStar(require("bigint-conversion"));
const paillierBigint = __importStar(require("paillier-bigint"));
const bitLength = 1024;
async function main() {
    const keyPair = await (0, rsa_1.generateKeys)(bitLength);
    const PORT = app_1.default.get('PORT');
    await app_1.default.listen(PORT);
    console.log('Servidor abierto en: ', PORT);
    return keyPair;
}
async function getCEkeys() {
    const response = await (0, node_fetch_1.default)("http://localhost:8080/rsa/pubk_ce", {
        method: 'POST',
        body: JSON.stringify({
            username: 'admin',
        }),
        headers: { 'Content-Type': 'application/json',
        }
    });
    const data = await response.json();
    const pubk_ceJS = (JSON.parse(JSON.stringify(data)));
    const pubk_ce = new rsa_1.RsaPublicKey(bic.base64ToBigint(pubk_ceJS.e), bic.base64ToBigint(pubk_ceJS.n));
    return pubk_ce;
}
async function startPaillier() {
    const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(bitLength);
    const paillierSys = new paillier_1.default(publicKey, privateKey);
    return paillierSys;
}
const keys = main();
exports.keys = keys;
const pubk_ce = getCEkeys();
exports.pubk_ce = pubk_ce;
const paillierSys = startPaillier();
exports.paillierSys = paillierSys;
//# sourceMappingURL=index.js.map