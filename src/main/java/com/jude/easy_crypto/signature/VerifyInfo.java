package com.jude.easy_crypto.signature;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class VerifyInfo {
    PublicKey publicKey;
    Signature signature;

    byte[] verifyTarget;
    byte[] sign;

}
