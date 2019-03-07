package com.jude.easy_crypto.keyreader;

public class KeyReaderKeyContent<KeyType> {

    private final KeyInfo keyInfo;

    public KeyReaderKeyContent(KeyInfo keyInfo) {
        this.keyInfo = keyInfo;
    }

    public KeyReaderPassword<KeyType> pemFile(String filePath){
        keyInfo.keyEncodeType = KeyEncodeType.PEM;
        keyInfo.file = filePath;
        return new KeyReaderPassword<>(keyInfo);
    }

}
