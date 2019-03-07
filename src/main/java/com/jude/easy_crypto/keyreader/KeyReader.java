package com.jude.easy_crypto.keyreader;

import java.io.IOException;

public class KeyReader<T> {

    final KeyInfo keyInfo;

    public KeyReader(KeyInfo keyInfo) {
        this.keyInfo = keyInfo;
    }

    public T read() throws IOException {
        if (keyInfo.keyEncodeType != KeyEncodeType.PEM) {
            throw new IOException("unsupported key type");
        }

        if (keyInfo.isPrivate) {
            if (keyInfo.file != null) {
                if (keyInfo.password == null) {
                    return (T) KeyTool.readPrivateKeyFromPem(keyInfo.file);
                } else {
                    return (T) KeyTool.readPrivateKeyFromPem(keyInfo.file, keyInfo.password);
                }
            } else {
                throw new IOException("key file not found");
            }
        } else {
            if (keyInfo.file != null) {
                if (keyInfo.password == null) {
                    return (T) KeyTool.readPublicKeyFromPem(keyInfo.file);
                } else {
                    throw new IOException("public key with password is unsupported");
                }
            } else {
                throw new IOException("key file not found");
            }
        }
    }
}
