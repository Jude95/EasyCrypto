package com.jude.easy_crypto.signature;

public class VerifyHandlerForTarget {

    private final VerifyInfo verifyInfo;

    public VerifyHandlerForTarget(VerifyInfo verifyInfo) {
        this.verifyInfo = verifyInfo;
    }

    public VerifyHandler targetAndSign(byte[] target, byte[] sign){
        verifyInfo.verifyTarget = target;
        verifyInfo.sign = sign;
        return new VerifyHandler(verifyInfo);
    }
}
