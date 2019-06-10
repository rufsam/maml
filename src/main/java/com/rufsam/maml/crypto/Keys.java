package com.rufsam.maml.crypto;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public final class Keys {

    public static String publicKeyToString(PublicKey publicKey) {
        try {
            KeyFactory fact = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec spec = fact.getKeySpec(publicKey, X509EncodedKeySpec.class);
            return Base64.getEncoder().encodeToString(spec.getEncoded());
        } catch (Exception e) { return null; }
    }

    public static String privateKeyToString(PrivateKey privateKey) {
        try {
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec spec = fact.getKeySpec(privateKey, PKCS8EncodedKeySpec.class);
            byte[] packed = spec.getEncoded();
            String key64 = Base64.getEncoder().encodeToString(packed);
            Arrays.fill(packed, (byte) 0);
            return key64;
        } catch(Exception e) { return null; }
    }

    public static PrivateKey loadPrivateKey(String s) {
        try {
            byte[] clear = Base64.getDecoder().decode(s);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(clear);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            PrivateKey priv = fact.generatePrivate(keySpec);
            Arrays.fill(clear, (byte) 0);
            return priv;
        } catch (Exception e) { return null; }
    }

    public static PublicKey loadPublicKey(String s) {
        try {
            byte[] data =  Base64.getDecoder().decode(s);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(data);
            KeyFactory fact = KeyFactory.getInstance("RSA");
            return fact.generatePublic(spec);
        } catch (Exception e) { return null; }
    }

}
