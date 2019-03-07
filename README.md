# EasyCrypto
简单的非对称加密库

# Dependency
```java
implementation 'me.jinuo:easy-crypto:1.0.0'
```

# Usage
```java
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
```

# Generate KeyPair
```
openssl

genrsa -out private_key.pem 2048
rsa -in private_key.pem -pubout -out public_key.pem
```