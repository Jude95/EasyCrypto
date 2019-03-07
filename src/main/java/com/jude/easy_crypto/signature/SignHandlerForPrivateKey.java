package com.jude.easy_crypto.signature;

import java.security.PrivateKey;

public class SignHandlerForPrivateKey {
    private final SignInfo signInfo;

    public SignHandlerForPrivateKey(SignInfo signInfo) {
        this.signInfo = signInfo;
    }

    public SignHandlerForTarget usePrivateKey(PrivateKey privateKey){
        signInfo.privateKey = privateKey;
        return new SignHandlerForTarget(signInfo);
    }

}
