package com.jude.easy_crypto.keyreader;

import com.jude.easy_crypto.UnknownKeyFileType;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.io.StringReader;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

public class KeyTool {
    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    private static PrivateKey readPrivateKeyFromPem(Reader reader, String password) throws IOException {
        PEMParser pemParser = new PEMParser(reader);
        Object object = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        if (object instanceof PEMEncryptedKeyPair) {
            PEMEncryptedKeyPair ckp = (PEMEncryptedKeyPair) object;
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
            KeyPair kp = converter.getKeyPair(ckp.decryptKeyPair(decProv));
            return kp.getPrivate();
        } else {
            throw new UnknownKeyFileType(object.getClass().getName()+" is not a pem_nopwd");
        }
    }

    private static PrivateKey readPrivateKeyFromPem(Reader reader) throws IOException {
        PEMParser pemParser = new PEMParser(reader);
        Object object = pemParser.readObject();
        JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");

        if (object instanceof PEMKeyPair) {
            PEMKeyPair ukp = (PEMKeyPair) object;
            KeyPair kp = converter.getKeyPair(ukp);
            return kp.getPrivate();
        } else {
            throw new UnknownKeyFileType(object.getClass().getName()+" is not a pem_nopwd");
        }
    }

    private static PublicKey readPublicKeyFromPem(Reader reader) throws IOException {
        try {
            PemObject spki = new PemReader(reader).readPemObject();
            return KeyFactory.getInstance("RSA", "BC").generatePublic(new X509EncodedKeySpec(spki.getContent()));
        }catch (Exception e){
            throw new UnknownKeyFileType("not a pem_nopwd");
        }
    }

    public static PrivateKey readPrivateKeyFromPem(String filepath) throws IOException {
        return readPrivateKeyFromPem(new FileReader(filepath));
    }

    public static PrivateKey readPrivateKeyFromPem(String filepath, String password) throws IOException {
        return readPrivateKeyFromPem(new FileReader(filepath), password);
    }

    public static PublicKey readPublicKeyFromPem(String filepath) throws IOException {
        return readPublicKeyFromPem(new FileReader(filepath));
    }

    public static PrivateKey readPrivateKeyFromPemString(String content) throws IOException {
        return readPrivateKeyFromPem(new StringReader(content));
    }

    public static PrivateKey readPrivateKeyFromPemString(String content, String password) throws IOException {
        return readPrivateKeyFromPem(new StringReader(content), password);
    }

    public static PublicKey readPublicKeyFromPemString(String content) throws IOException {
        return readPublicKeyFromPem(new StringReader(content));
    }

}
