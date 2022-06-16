
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
	const vote = new Voto(pubk_user, bic.base64ToBigint(msg.pubK_user_signed), msg.vote_encrypted, msg.vote_signed);
	console.log("CHECK"+vote);//Verifico la firma viendo si coincide con el resumen de la clave publica del usuario
	console.log(bic.base64ToBigint(msg.pubK_user_signed));
	console.log((await pubk_ce).n);
	const resumen_firma = (await pubk_ce).verify(bic.base64ToBigint(msg.pubK_user_signed));
	console.log("obtengo tras firmar: "+bic.bigintToBase64(resumen_firma));
	const resumen_clave = sha.digest(pubk_ce, 'SHA-256');
	console.log("Y el resumen da: " + await resumen_clave);
	if (bic.bigintToBase64(resumen_firma) === await resumen_clave) {
		//Verifico el voto viendo si coincide la firma del resumen del voto encriptado con el resumen del voto encriptau
		const resumen_firma_voto = vote.pubk_user.verify(bic.textToBigint(vote.vote_signed));
		const resumen_voto = bic.textToBigint(await sha.digest(vote.vote_encrypted));
		if (resumen_firma_voto === resumen_voto) {
			//El voto es legítimo y vamos a efectuar paillier
			paillier.sumNumber(bic.textToBigint(vote.vote_encrypted));
			return res.status(201).json({
				message: "Vote correctly realized"
			});
		}
		else {
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
