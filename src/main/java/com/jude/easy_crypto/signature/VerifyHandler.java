package com.jude.easy_crypto.signature;

import java.security.InvalidKeyException;
import java.security.SignatureException;

public class VerifyHandler {
    private final VerifyInfo verifyInfo;

    public VerifyHandler(VerifyInfo verifyInfo) {
        this.verifyInfo = verifyInfo;
    }

    public boolean verify() throws SignatureException, InvalidKeyException {
        return SignatureTool.verify(verifyInfo.signature, verifyInfo.publicKey,verifyInfo.verifyTarget,verifyInfo.sign);
    }
}
