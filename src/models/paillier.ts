import * as paillierBigint from 'paillier-bigint';
import * as bic from 'bigint-conversion';


export class PaillierSys {

    public publicKey: paillierBigint.PublicKey;
    public privateKey: paillierBigint.PrivateKey;
    public count: bigint;
    public counter: string;

    constructor(pubk: paillierBigint.PublicKey, privk: paillierBigint.PrivateKey) {
        this.publicKey= pubk;
        this.privateKey= privk;
        this.count = this.publicKey.encrypt(0n);
        this.counter = "0";
    }

}

export default PaillierSys;