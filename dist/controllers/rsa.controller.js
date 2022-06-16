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
const paillier = __importStar(require("./paillier.controller"));
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
    //añadir condicion login
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
    console.log("CHECK" + bic.bigintToBase64(vote.pubK_user_signed)); //Verifico la firma viendo si coincide con el resumen de la clave publica del usuario
    const resumen_firma = (await index_2.pubk_ce).verify(vote.pubK_user_signed);
    const a = bic.bigintToBase64(resumen_firma);
    console.log("obtengo tras firmar: " + bic.bigintToBase64(resumen_firma));
    const resumen_clave = sha.digest(pubk_user.toJsonString(), 'SHA-256');
    console.log("Y el resumen da: " + await resumen_clave);
    const b = await resumen_clave;
    if (a == b) {
        console.log("Firma verificada!!" + vote.vote_signed);
        //Verifico el voto viendo si coincide la firma del resumen del voto encriptado con el resumen del voto encriptau
        const resumen_firma_voto = vote.pubk_user.verify(bic.base64ToBigint(await vote.vote_signed));
        console.log("Firma comprobada: " + bic.bigintToBase64(resumen_firma_voto));
        console.log("voto encriptau: " + vote.vote_encrypted);
        const voto_unencrypted = (await index_3.paillierSys).privateKey.decrypt(bic.base64ToBigint(vote.vote_encrypted));
        console.log("Desencripto y obtengo: " + bic.bigintToBase64(await voto_unencrypted));
        var parsedVote = parseVote(bic.bigintToBase64(await voto_unencrypted));
        console.log(Number(parsedVote[0] + parsedVote[1]));
        var individualVote = (parsedVote[0] + parsedVote[1] + "/");
        console.log(individualVote);
        const test_vote_hash = sha.digest(individualVote, 'SHA-256');
        console.log(await test_vote_hash);
        const resumen_voto = bic.textToBigint(await sha.digest(vote.vote_encrypted));
        if (bic.bigintToBase64(resumen_firma_voto) === await test_vote_hash) {
            //El voto es legítimo y vamos a efectuar paillier
            console.log(BigInt(parsedVote[0] + parsedVote[1]));
            paillier.sumNumber(BigInt(parsedVote[0] + parsedVote[1]));
            var encryptedSum = (await index_3.paillierSys).publicKey.addition(bic.base64ToBigint(vote.vote_encrypted) + (await index_3.paillierSys).count);
            console.log((await index_3.paillierSys).privateKey.decrypt((await index_3.paillierSys).count));
            return res.status(201).json({
                message: "Vote correctly realized"
            });
        }
        else {
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
    return [num.substring(0, 3), num.substring(3, 6)];
}
function zeroPad(num) {
    return num.toString().padStart(4, "0");
}
//# sourceMappingURL=rsa.controller.js.map