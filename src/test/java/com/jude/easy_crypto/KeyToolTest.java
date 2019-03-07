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
    public void readPrivateKeyFromPemString() throws IOException {
        PrivateKey privateKey = EasyCrypto.readKey()
                .privateKey()
                .pemString("-----BEGIN RSA PRIVATE KEY-----\n" +
                        "MIICXQIBAAKBgQDAFpNgqO/A1y9F5KNNd+ZcLgBLzYNRWVcUAo07SciiIGeoAFTX\n" +
                        "Hx5Z0mpeix7XLInby57LPDmp4d+zw4Pulo4IphywM2gE85m7Hhw8OBaRMDR4kM+U\n" +
                        "lCJzA5ZC4AktgG9PN59H1UtfJj8ji/ixXPRfv+t4DCABSsmNBURuS4ygDwIDAQAB\n" +
                        "AoGBALvhGPNxKVe/4VAGiqeJ/7nnkIiUEb4umRpMSKFV0LSq51gOQu1KVaBbS4j/\n" +
                        "oAGsYYanCcEVPf1onSoxsMhbX71pDN4DmyMiolond9AU62+a+L6he+YcFxhx6iaL\n" +
                        "oSj0wVts2UiucvJJIZ87b3xlHLrhzyvDj+zy9EJxBjPb+7gpAkEA7bD39fjqNNag\n" +
                        "bIpai6gyf/GXibSYiLj6h/dWz5trujoDS4vI1xZXlIf7iHOxga9SPJfP10uguBMe\n" +
                        "AiUmLjYdhQJBAM7iXDYY017nSLWxBKjPjvNiy1M5IW8BiVkmGE+skkskIorrLG+0\n" +
                        "nQBF+jrSRi/oXPMQ9L4eQS3a3tzP5DYmAYMCQEeoqLjhWEqhwi+27mFYThFAlr0P\n" +
                        "U0U072L6cJOaebnlL4UhGWWu+Kxw6qZSqts8LgDSi/iOdl/Ic62V4ZLhAbkCQE6d\n" +
                        "pfzIoknGCdNBWUvs052ZRTpy00mjg9XkrAhaw5zaNmYjx9cLAz4/WT9Q+GrsGaYk\n" +
                        "I1y7knkiWt3+AfKxrpECQQClOTGZIOa7ZbPpN1b680pQT/K1Sjm/NZLA/TdqPLbM\n" +
                        "CSiaxBCbVK28Vyv0BWOrsEHYACL3vi4cK0wVpMQuOhfD\n" +
                        "-----END RSA PRIVATE KEY-----\n")
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
    public void readPublicKeyFromPemString() throws IOException {
        PublicKey publicKey  = EasyCrypto.readKey()
                .publicKey()
                .pemString("-----BEGIN PUBLIC KEY-----\n" +
                        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDAFpNgqO/A1y9F5KNNd+ZcLgBL\n" +
                        "zYNRWVcUAo07SciiIGeoAFTXHx5Z0mpeix7XLInby57LPDmp4d+zw4Pulo4Iphyw\n" +
                        "M2gE85m7Hhw8OBaRMDR4kM+UlCJzA5ZC4AktgG9PN59H1UtfJj8ji/ixXPRfv+t4\n" +
                        "DCABSsmNBURuS4ygDwIDAQAB\n" +
                        "-----END PUBLIC KEY-----\n")
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