package com.rufsam.maml.crypto;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.google.common.hash.Hashing;

public class AES {

	private static byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	private static IvParameterSpec ivspec = new IvParameterSpec(iv);

	public static String encrypt(String plainText, String password) throws AESException {
		try {
			byte[] p = Hashing.sha256().hashString(password, StandardCharsets.UTF_8).asBytes();
			SecretKeySpec secretKey = new SecretKeySpec(p, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
			return Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes()));
		} catch (Exception e) {
			throw new AESException(e);
		}
	}

	public static String decrypt(String cipherText, String password) throws AESException {
		try {
			byte[] p = Hashing.sha256().hashString(password, StandardCharsets.UTF_8).asBytes();
			SecretKeySpec secretKey = new SecretKeySpec(p, "AES");
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.DECRYPT_MODE, secretKey, ivspec);
			return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText.getBytes())));
		} catch (Exception e) {
			throw new AESException(e);
		}
	}

	public static class AESException extends Exception {
		public AESException(Throwable e) {
			super(e);
		}
	}

}