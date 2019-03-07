package com.jude.easy_crypto.signature;

public class SignHandlerForTarget {
    private final SignInfo signInfo;

    public SignHandlerForTarget(SignInfo signInfo) {
        this.signInfo = signInfo;
    }

    public SignHandler target(byte[] content){
        signInfo.content = content;
        return new SignHandler(signInfo);
    }

}
