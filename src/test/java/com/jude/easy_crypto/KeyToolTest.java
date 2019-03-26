package com.jude.easy_crypto;

import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.UTF8;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;

public class KeyToolTest {


    @Test
    public void readPrivateKeyFromPem() throws IOException {
        PrivateKey privateKey = EasyCrypto.readKey()
                .privateKey()
                .pemFile(ResourceLoader.getResource("pem_nopwd/private_key.pem").getPath())
                .noPassword()
                .read();

        Assert.assertNotNull(privateKey);
    }

    @Test
    public void readPrivateKeyFromPemString() throws IOException {
        PrivateKey privateKey = EasyCrypto.readKey()
                .privateKey()
                .pemString("-----BEGIN RSA PRIVATE KEY-----\n" +
                        "MIICWwIBAAKBgQDlNT1aqd0aCTXRA6pD2suPaBUz/rzEkwfi7BcazMWQjzAGkqLT\n" +
                        "CZsgOPm9gSgA7jk+aQAMdlrn2QnprNL9sJs0A232C9UzO5d9pcJYs0YNJEQ9mOFw\n" +
                        "Qpnz4llmdcYC36psyNqK/wqCWp+XNrG723Fi0PiJLJXraMCHUb0VyNnclQIDAQAB\n" +
                        "AoGAHWxpNONLY9U82FkNGWrT6NPmrOcNmnp5b7L5AFK7JeSLuLxINKkuBcPqo14a\n" +
                        "IYxzQsS94durrcmZ0SqDZ1ethJCdwImPnII5WFSr7N6ya7hT39daSVElqHaXDjhV\n" +
                        "5CtYQ1U2l6LTkgY2//YYR2oY0Ed2lW2buWU5ntpZUmJAsJ0CQQD1NsuCu6JLC6Jz\n" +
                        "Q1lBxZTm3S5mBkcSEsW/MPCEl2zHO9Clad2J5Cmq54s7Ma0jC4Vix7XHbPZqqo5O\n" +
                        "ZJG3POHXAkEA70o1yOe4n8q8fmitRA/163Bdk70Lz/Jkz5V+c0sdCpLcXBn1j9Rv\n" +
                        "k1u4NU7mJZnbWlMfZrUNbbrOBIb1dee/cwJAaH/egKsnwaWGqGpGKnJiP3R45n+8\n" +
                        "X+ZiIVVg2pCRieJiy2tvPuleHHgqbKKB71JkmLEVNZSo+tIObTgMpTMr5wJAFEdj\n" +
                        "u3z3xoL16niQhn4bxzIknAqfX6YZKQZwSvEIqwa7KgsBJolIU2Kof8wJ8RHS5xq4\n" +
                        "RIn/c1crcnLFhpJ3RQJAMJyRYQtOOUWpArzjhksw/0U3zyLeUSz8AZfsnBt6+vYZ\n" +
                        "YfLiGVLpg2AsVPYxTSWsM4E46LLv8/JOomaeGq5Ugg==\n" +
                        "-----END RSA PRIVATE KEY-----\n")
                .noPassword()
                .read();

        Assert.assertNotNull(privateKey);
    }

    @Test
    public void readPublicKeyFromPem() throws IOException {
        PublicKey publicKey  = EasyCrypto.readKey()
                .publicKey()
                .pemFile(ResourceLoader.getResource("pem_nopwd/public_key.pem").getPath())
                .noPassword()
                .read();

        Assert.assertNotNull(publicKey);
    }

    @Test
    public void readPublicKeyFromPemString() throws IOException {
        PublicKey publicKey  = EasyCrypto.readKey()
                .publicKey()
                .pemString("-----BEGIN PUBLIC KEY-----\n" +
                        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDlNT1aqd0aCTXRA6pD2suPaBUz\n" +
                        "/rzEkwfi7BcazMWQjzAGkqLTCZsgOPm9gSgA7jk+aQAMdlrn2QnprNL9sJs0A232\n" +
                        "C9UzO5d9pcJYs0YNJEQ9mOFwQpnz4llmdcYC36psyNqK/wqCWp+XNrG723Fi0PiJ\n" +
                        "LJXraMCHUb0VyNnclQIDAQAB\n" +
                        "-----END PUBLIC KEY-----\n")
                .noPassword()
                .read();

        Assert.assertNotNull(publicKey);
    }

    @Test
    public void sign() throws Exception {
        PrivateKey privateKey = EasyCrypto.readKey()
                .privateKey()
                .pemFile(ResourceLoader.getResource("pem_nopwd/private_key.pem").getPath())
                .noPassword()
                .read();

        PublicKey publicKey  = EasyCrypto.readKey()
                .publicKey()
                .pemFile(ResourceLoader.getResource("pem_nopwd/public_key.pem").getPath())
                .noPassword()
                .read();

        byte[] signature = EasyCrypto.sign()
                .algorithm("SHA256withRSA")
                .usePrivateKey(privateKey)
                .target("abcdefg".getBytes(StandardCharsets.UTF_8))
                .sign();

        System.out.println(Base64.toBase64String(signature));

        boolean result = EasyCrypto.verify()
                .algorithm("SHA256withRSA")
                .usePublickKey(publicKey)
                .targetAndSign("abcdefg".getBytes(StandardCharsets.UTF_8), signature)
                .verify();

        Assert.assertTrue(result);


        boolean result2 = EasyCrypto.verify()
                .algorithm("SHA256withRSA")
                .usePublickKey(publicKey)
                .targetAndSign("abcdefgh".getBytes(StandardCharsets.UTF_8), signature)
                .verify();

        Assert.assertFalse(result2);

    }


}