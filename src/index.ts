import app from "./app";
import {generateKeys, RsaKeyPair, RsaPublicKey} from '@scbd/rsa';
import fetch from 'node-fetch';
import PaillierSys from "./models/paillier";
import * as bic from 'bigint-conversion';
import * as paillierBigint from 'paillier-bigint';
const bitLength = 1024;


async function main() {
  const keyPair: RsaKeyPair = await generateKeys(bitLength);
  const PORT = app.get('PORT');
  await app.listen(PORT);
  console.log('Servidor abierto en: ', PORT);
  return keyPair;
}

async function getCEkeys() {
  const response = await fetch("http://localhost:8080/rsa/pubk_ce", {
      method: 'POST',
      body: JSON.stringify({
        username: 'admin',
      }),
      headers: {'Content-Type': 'application/json',
    } 
    });
    const data = await response.json();
    const pubk_ceJS = (JSON.parse(JSON.stringify(data)));
    const pubk_ce = new RsaPublicKey(bic.base64ToBigint(pubk_ceJS.e), bic.base64ToBigint(pubk_ceJS.n));
    return pubk_ce;
}

async function startPaillier() {
  const { publicKey, privateKey } = await paillierBigint.generateRandomKeys(bitLength);
  const paillierSys = new PaillierSys(publicKey, privateKey);
  return paillierSys;
}

const keys = main();
const pubk_ce = getCEkeys();
const paillierSys = startPaillier();
export { keys };
export { pubk_ce };
export { paillierSys };