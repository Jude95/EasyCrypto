package com.jude.easy_crypto.keyreader;

public class KeyReaderKeyContent<KeyType> {

    private final KeyInfo keyInfo;

    public KeyReaderKeyContent(KeyInfo keyInfo) {
        this.keyInfo = keyInfo;
    }

    public KeyReaderPassword<KeyType> pemString(String content){
        keyInfo.keyEncodeType = KeyEncodeType.PEM;
        keyInfo.content = content;
        return new KeyReaderPassword<>(keyInfo);
    }


    public KeyReaderPassword<KeyType> pemFile(String filePath){
        keyInfo.keyEncodeType = KeyEncodeType.PEM;
        keyInfo.file = filePath;
        return new KeyReaderPassword<>(keyInfo);
    }

}
