package com.jude.easy_crypto.signature;

import java.security.*;

public class SignatureTool {

    public static byte[] sign(Signature signature, PrivateKey privateKey, byte[] content) throws InvalidKeyException, SignatureException {
        signature.initSign(privateKey);
        signature.update(content);
        return signature.sign();
    }

    public static boolean verify(Signature signature, PublicKey publicKey, byte[] content, byte[] sign) throws InvalidKeyException, SignatureException {
        signature.initVerify(publicKey);
        signature.update(content);
        return signature.verify(sign);
    }

}
