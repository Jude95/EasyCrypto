package com.jude.easy_crypto.signature;

import java.security.PrivateKey;
import java.security.Signature;

public class SignInfo {
    byte[] content;
    PrivateKey privateKey;
    Signature signature;
}
