import {generateKeys, RsaKeyPair, RsaPublicKey} from '@scbd/rsa';

class Voto {

    public pubk_user: RsaPublicKey;
    public pubK_user_signed: bigint;
    public vote_encrypted: string;
    public vote_signed: string;

    constructor(pubk_user: RsaPublicKey, pubk_user_signed: bigint, vote_encrypted: string, vote_signed: string) {
        this.pubk_user = pubk_user,
        this.pubK_user_signed = pubk_user_signed,
        this.vote_encrypted = vote_encrypted,
        this.vote_signed = vote_signed
    }

    public getpubk_user(): RsaPublicKey {
        return this.pubk_user;
    }

    public getpubk_user_signed(): bigint {
        return this.pubK_user_signed;
    }

    public getvote_encypted(): string {
        return this.vote_encrypted;
    }

    public getvote_signed(): string {
        return this.vote_signed;
    }

}

export default Voto;