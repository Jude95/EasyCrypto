package com.jude.easy_crypto;

import com.jude.easy_crypto.keyreader.KeyInfo;
import com.jude.easy_crypto.keyreader.KeyReaderKeyType;
import com.jude.easy_crypto.signature.*;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;

public class EasyCrypto {

    public static KeyReaderKeyType readKey(){
        return new KeyReaderKeyType(new KeyInfo());
    }

    public static SignHandlerForAlgorithm sign(){
        return new SignHandlerForAlgorithm(new SignInfo());
    }

    public static VerifyHandlerForAlgorithm verify(){
        return new VerifyHandlerForAlgorithm(new VerifyInfo());
    }

}
