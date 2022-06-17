import * as paillierBigint from 'paillier-bigint';
import * as bic from 'bigint-conversion';


export class PaillierSys {

    public publicKey: paillierBigint.PublicKey;
    public privateKey: paillierBigint.PrivateKey;
    public count: bigint;
    public counter: string[];

    constructor(pubk: paillierBigint.PublicKey, privk: paillierBigint.PrivateKey) {
        this.publicKey= pubk;
        this.privateKey= privk;
        this.count = this.publicKey.encrypt(0n);
        this.counter = ["0","0"];
    }

    public getResoults(): Number[] {
        var res : Number[] = [0,0];
        res[0]= Number(this.counter[0]) / 1000 ;
        res[1] = Number(this.counter[1]);
        return res;

    }

    public getRes(): String {
        var res : Number[] = [0,0];
        res[0]= Number(this.counter[0]) /1000;
        res[1]= Number(this.counter[1]);
        if (res[0] == 0.001) {
            res[0] = 1;
        }
        return "Laporta tiene: "+res[0]+" | Bartomeu tiene: "+res[1];
    }

}

export default PaillierSys;