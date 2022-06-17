
import {Request, Response} from 'express';
import {generateKeys, RsaPublicKey, RsaPrivateKey, RsaKeyPair} from '@scbd/rsa';
import * as sha from 'object-sha';
import * as bic from 'bigint-conversion';
import * as paillier from './paillier.controller'
import userList from '../data';
import { keys } from '../index';
import { PaillierResults } from '../models/results'
import { pubk_ce } from '../index';
import { paillierSys } from '../index';
import Voto from '../models/voto';
const bitLength = 1024;

export async function generateBothKeys(req: Request, res: Response): Promise<Response>{
    const keyPair: RsaKeyPair = await generateKeys(bitLength);
    const key = {
        e: bic.bigintToBase64(keyPair.publicKey.e),
		n: bic.bigintToBase64(keyPair.publicKey.n)
    }
    return res.status(201).json(key);
}

export async function getServerPubK(req: Request, res: Response): Promise<Response>{
	//añadir condicion login
	console.log(req.body);
	const username = req.body;
	const check = userList.find((obj) => {
		return obj.username === username.username;
	})
	//Si no encontramos el usuario en la lista (archivo data.ts), le denegaremos el acceso a la clave
	if (check === undefined) {
		const error = {
			message: "You are not authorized"
		}
		return res.status(401).json(error);
	}
	else {
		const key = {
			e: bic.bigintToBase64(await (await keys).publicKey.e),
			n: bic.bigintToBase64(await (await keys).publicKey.n)
		}
		return res.status(201).json(key);
	}
}

export async function getPaillier(req: Request, res: Response): Promise<Response>{
	console.log((await paillierSys).publicKey.g);
	const key = {
		g: bic.bigintToBase64(await (await paillierSys).publicKey.g),
		n: bic.bigintToBase64(await (await paillierSys).publicKey.n)
	}
	return res.status(201).json(key);
}

export async function signMsg(req: Request, res: Response): Promise<Response>{
	const msg = req.body
	const privKey: RsaPrivateKey = await (await keys).privateKey;
	const signed: string = await bic.bigintToBase64(privKey.sign(msg))

	return res.status(201).json({signature: signed});
}

export async function checkVotes(req: Request, res: Response): Promise<Response> {
	const username = req.body;
	if (username === "admin") {
		const final = splitNum(Number((await paillierSys).count), 3);
		const v1: number = Number(final[0]);
		const v2: number = Number(final[1]);
		const results= new PaillierResults(v1, v2);
		var json = JSON.stringify(results);
		return res.status(201).json(json);
	}
	else {
		const error = {
			message: "You are not authorized"
		}
		return res.status(401).json(error);
	}
}

export async function vote(req: Request, res: Response): Promise<Response>{
	const msg = (JSON.parse(JSON.stringify(req.body)));
	const pubk_user = new RsaPublicKey(bic.base64ToBigint(msg.pubk_user_e), bic.base64ToBigint(msg.pubk_user_n));
	const vote = new Voto(pubk_user, bic.base64ToBigint(msg.pubK_user_signed), msg.encrypt_pubks, msg.sign_privc);
	//Verifico la firma viendo si coincide con el resumen de la clave publica del usuario
	const resumen_firma = (await pubk_ce).verify(vote.pubK_user_signed);
	const a = bic.bigintToBase64(resumen_firma);
	console.log("Obtengo tras firmar: "+bic.bigintToBase64(resumen_firma));
	const resumen_clave = sha.digest(pubk_user.toJsonString(), 'SHA-256');
	console.log("Y si resumo la clave que me ha enviado el votante: " + await resumen_clave);
	const b= await resumen_clave;
	if (a == b) {
		//Verifico el voto viendo si coincide la firma del resumen del voto encriptado con el resumen del voto encriptau
		const resumen_firma_voto = bic.bigintToBase64(vote.pubk_user.verify(bic.base64ToBigint(await vote.vote_signed)));
		console.log("Tengo ahora mismo: "+((await paillierSys).privateKey.decrypt((await paillierSys).count)));
		const check_hash = sha.digest(vote.vote_encrypted, 'SHA-256');
		console.log("Comparo con: "+await check_hash);
		if ((resumen_firma_voto) === await check_hash) {
			console.log("el voto es : "+Number(bic.bigintToBase64((await paillierSys).privateKey.decrypt(bic.base64ToBigint(vote.vote_encrypted)))));
			console.log("Firma comprobada: "+ (resumen_firma_voto));
			var suma = (await paillierSys).publicKey.addition((await paillierSys).publicKey.encrypt(BigInt(Number(bic.bigintToBase64((await paillierSys).privateKey.decrypt(bic.base64ToBigint(vote.vote_encrypted)))))), (await paillierSys).count);
			(await paillierSys).count = suma
			var nuevo = bic.bigintToBase64((await paillierSys).privateKey.decrypt(suma));
			(await paillierSys).counter = parseVote(((await paillierSys).privateKey.decrypt((await paillierSys).count)).toString());
			(await paillierSys).count= (await paillierSys).publicKey.encrypt(bic.base64ToBigint(nuevo));
			console.log((await paillierSys).getRes());
			return res.status(201).json({
				message: "Vote correctly realized"
			});
		}
		{
			const error = {
				message: "You are not authorized"
			}
			return res.status(401).json(error);
		}
	}
	else {
		const error = {
			message: "You are not authorized"
		}
		return res.status(401).json(error);
	}
}

function splitNum(num: number, pos: number) {
	const s: string = num.toString();
	return [s.substring(0, pos), s.substring(pos)];
   }

function parseVote(num: String) {
	return [num.substring(0,4), num.substring(4,8)];
}

function zeroPad(num: Number) {
	return num.toString().padStart(4, "0");
  }
  