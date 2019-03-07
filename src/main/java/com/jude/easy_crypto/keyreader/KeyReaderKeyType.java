package com.jude.easy_crypto.keyreader;

import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyReaderKeyType {

    private final KeyInfo keyInfo;

    public KeyReaderKeyType(KeyInfo keyInfo) {
        this.keyInfo = keyInfo;
    }

    public KeyReaderKeyContent<PrivateKey> privateKey(){
        keyInfo.isPrivate = true;
        return new KeyReaderKeyContent<PrivateKey>(keyInfo);
    }

    public KeyReaderKeyContent<PublicKey> publicKey(){
        keyInfo.isPrivate = false;
        return new KeyReaderKeyContent<PublicKey>(keyInfo);
    }

}
