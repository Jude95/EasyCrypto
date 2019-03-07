package com.jude.easy_crypto;

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
                .pemFile(ResourceLoader.getResource("pem_nopwd/private.pem").getPath())
                .noPassword()
                .read();

        Assert.assertNotNull(privateKey);
    }

    @Test
    public void readPublicKeyFromPem() throws IOException {
        PublicKey publicKey  = EasyCrypto.readKey()
                .publicKey()
                .pemFile(ResourceLoader.getResource("pem_nopwd/public.pem").getPath())
                .noPassword()
                .read();

        Assert.assertNotNull(publicKey);
    }

    @Test
    public void sign() throws Exception {
        PrivateKey privateKey = EasyCrypto.readKey()
                .privateKey()
                .pemFile(ResourceLoader.getResource("pem_nopwd/private.pem").getPath())
                .noPassword()
                .read();

        PublicKey publicKey  = EasyCrypto.readKey()
                .publicKey()
                .pemFile(ResourceLoader.getResource("pem_nopwd/public.pem").getPath())
                .noPassword()
                .read();

        byte[] signature = EasyCrypto.sign()
                .algorithm("SHA256withRSA")
                .usePrivateKey(privateKey)
                .target("abcdefg".getBytes(StandardCharsets.UTF_8))
                .sign();

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