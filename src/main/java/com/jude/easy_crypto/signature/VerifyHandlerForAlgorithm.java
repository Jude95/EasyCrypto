package com.jude.easy_crypto.signature;

import java.security.NoSuchAlgorithmException;
import java.security.Signature;

public class VerifyHandlerForAlgorithm {
    private final VerifyInfo verifyInfo;

    public VerifyHandlerForAlgorithm(VerifyInfo verifyInfo) {
        this.verifyInfo = verifyInfo;
    }

    public VerifyHandlerForPublicKey algorithm(String algorithm) throws NoSuchAlgorithmException {
        this.verifyInfo.signature = Signature.getInstance(algorithm);
        return new VerifyHandlerForPublicKey(verifyInfo);
    }

}
