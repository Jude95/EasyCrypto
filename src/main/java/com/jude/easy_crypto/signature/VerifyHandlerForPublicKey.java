package com.jude.easy_crypto.signature;

import java.security.PublicKey;

public class VerifyHandlerForPublicKey {

    private final VerifyInfo verifyInfo;

    public VerifyHandlerForPublicKey(VerifyInfo verifyInfo) {
        this.verifyInfo = verifyInfo;
    }

    public VerifyHandlerForTarget usePublickKey(PublicKey publicKey){
        verifyInfo.publicKey = publicKey;
        return new VerifyHandlerForTarget(verifyInfo);
    }
}
