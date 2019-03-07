package com.jude.easy_crypto.signature;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;

public class SignHandler {

    private final SignInfo signInfo;

    public SignHandler(SignInfo signInfo) {
        this.signInfo = signInfo;
    }

    public byte[] sign() throws InvalidKeyException, SignatureException {
        return SignatureTool.sign(signInfo.signature, signInfo.privateKey, signInfo.content);
    }
}
