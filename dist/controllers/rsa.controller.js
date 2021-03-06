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
exports.vote = exports.checkVotes = exports.signMsg = exports.getPaillier = exports.getServerPubK = exports.generateBothKeys = void 0;
const rsa_1 = require("@scbd/rsa");
const sha = __importStar(require("object-sha"));
const bic = __importStar(require("bigint-conversion"));
const data_1 = __importDefault(require("../data"));
const index_1 = require("../index");
const results_1 = require("../models/results");
const index_2 = require("../index");
const index_3 = require("../index");
const voto_1 = __importDefault(require("../models/voto"));
const bitLength = 1024;
async function generateBothKeys(req, res) {
    const keyPair = await (0, rsa_1.generateKeys)(bitLength);
    const key = {
        e: bic.bigintToBase64(keyPair.publicKey.e),
        n: bic.bigintToBase64(keyPair.publicKey.n)
    };
    return res.status(201).json(key);
}
exports.generateBothKeys = generateBothKeys;
async function getServerPubK(req, res) {
    //a??adir condicion login
    console.log(req.body);
    const username = req.body;
    const check = data_1.default.find((obj) => {
        return obj.username === username.username;
    });
    //Si no encontramos el usuario en la lista (archivo data.ts), le denegaremos el acceso a la clave
    if (check === undefined) {
        const error = {
            message: "You are not authorized"
        };
        return res.status(401).json(error);
    }
    else {
        const key = {
            e: bic.bigintToBase64(await (await index_1.keys).publicKey.e),
            n: bic.bigintToBase64(await (await index_1.keys).publicKey.n)
        };
        return res.status(201).json(key);
    }
}
exports.getServerPubK = getServerPubK;
async function getPaillier(req, res) {
    console.log((await index_3.paillierSys).publicKey.g);
    const key = {
        g: bic.bigintToBase64(await (await index_3.paillierSys).publicKey.g),
        n: bic.bigintToBase64(await (await index_3.paillierSys).publicKey.n)
    };
    return res.status(201).json(key);
}
exports.getPaillier = getPaillier;
async function signMsg(req, res) {
    const msg = req.body;
    const privKey = await (await index_1.keys).privateKey;
    const signed = await bic.bigintToBase64(privKey.sign(msg));
    return res.status(201).json({ signature: signed });
}
exports.signMsg = signMsg;
async function checkVotes(req, res) {
    const username = req.body;
    if (username === "admin") {
        const final = splitNum(Number((await index_3.paillierSys).count), 3);
        const v1 = Number(final[0]);
        const v2 = Number(final[1]);
        const results = new results_1.PaillierResults(v1, v2);
        var json = JSON.stringify(results);
        return res.status(201).json(json);
    }
    else {
        const error = {
            message: "You are not authorized"
        };
        return res.status(401).json(error);
    }
}
exports.checkVotes = checkVotes;
async function vote(req, res) {
    const msg = (JSON.parse(JSON.stringify(req.body)));
    const pubk_user = new rsa_1.RsaPublicKey(bic.base64ToBigint(msg.pubk_user_e), bic.base64ToBigint(msg.pubk_user_n));
    const vote = new voto_1.default(pubk_user, bic.base64ToBigint(msg.pubK_user_signed), msg.encrypt_pubks, msg.sign_privc);
    //Verifico la firma viendo si coincide con el resumen de la clave publica del usuario
    const resumen_firma = (await index_2.pubk_ce).verify(vote.pubK_user_signed);
    const a = bic.bigintToBase64(resumen_firma);
    console.log("Obtengo tras firmar: " + bic.bigintToBase64(resumen_firma));
    const resumen_clave = sha.digest(pubk_user.toJsonString(), 'SHA-256');
    console.log("Y si resumo la clave que me ha enviado el votante: " + await resumen_clave);
    const b = await resumen_clave;
    if (a == b) {
        //Verifico el voto viendo si coincide la firma del resumen del voto encriptado con el resumen del voto encriptau
        const resumen_firma_voto = bic.bigintToBase64(vote.pubk_user.verify(bic.base64ToBigint(await vote.vote_signed)));
        console.log("Tengo ahora mismo: " + ((await index_3.paillierSys).privateKey.decrypt((await index_3.paillierSys).count)));
        const check_hash = sha.digest(vote.vote_encrypted, 'SHA-256');
        console.log("Comparo con: " + await check_hash);
        if ((resumen_firma_voto) === await check_hash) {
            console.log("el voto es : " + Number(bic.bigintToBase64((await index_3.paillierSys).privateKey.decrypt(bic.base64ToBigint(vote.vote_encrypted)))));
            console.log("Firma comprobada: " + (resumen_firma_voto));
            var suma = (await index_3.paillierSys).publicKey.addition((await index_3.paillierSys).publicKey.encrypt(BigInt(Number(bic.bigintToBase64((await index_3.paillierSys).privateKey.decrypt(bic.base64ToBigint(vote.vote_encrypted)))))), (await index_3.paillierSys).count);
            (await index_3.paillierSys).count = suma;
            var nuevo = bic.bigintToBase64((await index_3.paillierSys).privateKey.decrypt(suma));
            console.log("recuento: " + ((await index_3.paillierSys).privateKey.decrypt((await index_3.paillierSys).count)));
            (await index_3.paillierSys).counter = parseVote(((await index_3.paillierSys).privateKey.decrypt((await index_3.paillierSys).count)).toString());
            (await index_3.paillierSys).count = (await index_3.paillierSys).publicKey.encrypt(bic.base64ToBigint(nuevo));
            console.log((await index_3.paillierSys).getRes());
            return res.status(201).json({
                message: "Vote correctly realized"
            });
        }
        {
            const error = {
                message: "You are not authorized"
            };
            return res.status(401).json(error);
        }
    }
    else {
        const error = {
            message: "You are not authorized"
        };
        return res.status(401).json(error);
    }
}
exports.vote = vote;
function splitNum(num, pos) {
    const s = num.toString();
    return [s.substring(0, pos), s.substring(pos)];
}
function parseVote(num) {
    return [num.substring(0, 4), num.substring(4, 8)];
}
function zeroPad(num) {
    return num.toString().padStart(4, "0");
}
//# sourceMappingURL=rsa.controller.js.map