package com.jude.easy_crypto.signature;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class SignHandlerForAlgorithm {
    private final SignInfo signInfo;

    public SignHandlerForAlgorithm(SignInfo signInfo) {
        this.signInfo = signInfo;
    }

    public SignHandlerForPrivateKey algorithm(String algorithm) throws NoSuchAlgorithmException {
        this.signInfo.signature = Signature.getInstance(algorithm);
        return new SignHandlerForPrivateKey(signInfo);
    }

}
