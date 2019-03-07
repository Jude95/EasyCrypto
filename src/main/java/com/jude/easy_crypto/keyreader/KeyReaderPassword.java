package com.jude.easy_crypto.keyreader;

public class KeyReaderPassword<KeyType> {
    private final KeyInfo keyInfo;


    public KeyReaderPassword(KeyInfo keyInfo) {
        this.keyInfo = keyInfo;
    }

    public KeyReader<KeyType> password(String password) {
        keyInfo.password = password;
        return new KeyReader<>(keyInfo);
    }

    public KeyReader<KeyType> noPassword() {
        keyInfo.password = null;
        return new KeyReader<>(keyInfo);
    }
}
