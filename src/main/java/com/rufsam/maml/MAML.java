package com.rufsam.maml;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;

import com.rufsam.maml.crypto.AES;
import com.rufsam.maml.crypto.Keys;
import com.rufsam.maml.crypto.RSA;
import org.json.JSONObject;

import com.google.common.hash.Hashing;

import jota.IotaAPI;
import jota.model.Bundle;
import jota.model.Transaction;
import jota.model.Transfer;
import jota.utils.TrytesConverter;

public class MAML {

	public static String protocol = "https";
	public static String host = "nodes.thetangle.org";
	public static String port = "443";
	public static int depth = 3;
	public static int minWeightMagnitude = 14;

	private IotaAPI api = new IotaAPI.Builder().protocol(protocol).host(host).port(port).build();

	private String rootAddress;
	private String channelPassword;
	private String currentWriteAddress;
	private String currentReadAddress;
	private Map<String, PublicKey> trustedAuthors = new HashMap<>();

	public MAML(String rootAddress) {
		this.rootAddress = rootAddress;
		this.channelPassword = "";
	}

	public MAML(String rootAddress, String channelPassword) {
		this(rootAddress);
		this.channelPassword = channelPassword;
	}

	public MessageResponse read() {

		String previousAddress = currentReadAddress;

		if(currentReadAddress == null)
			currentReadAddress = rootAddress;
		else
			currentReadAddress = hash(currentReadAddress + channelPassword);

		List<Transaction> x = null;
		String data = null;

		do {
			try {

				x = api.findTransactionObjectsByAddresses(new String[] { currentReadAddress });

				if (x.isEmpty()) {
					currentReadAddress = previousAddress;
					return null;
				}

				data = "";
				Bundle b = api.bundlesFromAddresses(new String[] {currentReadAddress}, false)[0];
				for (Transaction t : b.getTransactions())
					data += t.getSignatureFragments();

				break;

			} catch (Exception e) {
				e.printStackTrace();
			}
		} while (true);

		try {

			data = data.substring(0, data.indexOf("999999999"));
			data = TrytesConverter.trytesToAscii(data);

			JSONObject o = new JSONObject(data);

			String privateData = o.get("private").toString();

			String decryptedData = null;
			try {
				decryptedData = AES.decrypt(privateData, channelPassword);
			} catch (AES.AESException e) { decryptedData = privateData; }

			String signature = o.get("s").toString();
			String publicKeyHash = o.get("k").toString();

			boolean isTrusted = true;
            if(trustedAuthors.size() > 0) {
                String hash = Hashing.sha256().hashString(currentReadAddress + privateData, StandardCharsets.UTF_8).toString();
				isTrusted = trustedAuthors.containsKey(publicKeyHash) && RSA.verify(hash, signature, trustedAuthors.get(publicKeyHash));
            }

			Message ret = new Message();
            ret.setPrivateData(decryptedData);
			ret.setPublicKeyHash(publicKeyHash);
			ret.setSignature(signature);

			return new MessageResponse(currentReadAddress, hash(currentReadAddress + channelPassword), ret, true, isTrusted);

		} catch (Exception e) {
			return new MessageResponse(currentReadAddress, hash(currentReadAddress + channelPassword), null, false, false);
		}

	}

	public MessageResponse write(Message message, PrivateKey privateKey) throws RSA.RSAException, AES.AESException {

		if(currentWriteAddress == null)
			findEmptyAddress();
		 else
			currentWriteAddress = hash(currentWriteAddress + channelPassword);

		message.setPrivateData(AES.encrypt(message.getPrivateData(),channelPassword));

        String hash = Hashing.sha256().hashString(currentWriteAddress + message.getPrivateData(), StandardCharsets.UTF_8).toString();
		message.setSignature(RSA.sign(hash, privateKey));
		
		List<Transfer> transfers = new ArrayList<>();
		Transfer t = new Transfer(currentWriteAddress, 0, TrytesConverter.asciiToTrytes(message.toString()), "");
		transfers.add(t);
		
		boolean loop = true;
		do {
			try {
				api.sendTransfer(currentWriteAddress, 2, depth, minWeightMagnitude, transfers, null, currentWriteAddress, false, false, null);
				loop = false;
			} catch (Exception e) {
				e.printStackTrace();
			}
		} while (loop);

		return new MessageResponse(currentWriteAddress, hash(currentWriteAddress + channelPassword), message, true,true);

	}

	private void findEmptyAddress() {

		String currentReadAddress = this.currentReadAddress;

		if(currentReadAddress == null)
			currentReadAddress = rootAddress;

		List<Transaction> x = null;

		do {

			do {
				try {
					x = api.findTransactionObjectsByAddresses(new String[] { currentReadAddress });
					break;
				} catch (Exception e) { e.printStackTrace(); }
			} while (true);

			if(x.isEmpty())
				break;

			currentReadAddress = hash(currentReadAddress + channelPassword);

		} while(true);

		if(currentReadAddress.equals(rootAddress))
			currentWriteAddress = rootAddress;
		else
			currentWriteAddress = currentReadAddress;

	}

	public String split(String channelPassword) {
		this.channelPassword = channelPassword;
		currentReadAddress = currentWriteAddress;
		return hash(currentReadAddress + channelPassword);
	}

	public static String hash(String s) {
		String hash = Hashing.sha256().hashString(s, StandardCharsets.UTF_8).toString();
		hash = TrytesConverter.asciiToTrytes(hash).substring(0, 81);
		return hash;
	}

	public void addTrustedAuthor(PublicKey publicKey) {
		trustedAuthors.put(Hashing.sha256().hashString(Keys.publicKeyToString(publicKey), StandardCharsets.UTF_8).toString(), publicKey);
	}

	public void removeTrustedAuthor(PublicKey publicKey) {
		trustedAuthors.remove(Hashing.sha256().hashString(Keys.publicKeyToString(publicKey), StandardCharsets.UTF_8).toString());
	}

}