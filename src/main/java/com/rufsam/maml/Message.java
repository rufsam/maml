package com.rufsam.maml;

import com.google.common.hash.Hashing;
import com.rufsam.maml.crypto.Keys;
import org.json.JSONObject;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class Message {

	private String privateData;
	private String publicKeyHash;
	private String signature;

	public String getPrivateData() {
		return privateData;
	}

	public void setPrivateData(String privateData) {
		this.privateData = privateData;
	}

	public void setPublicKeyHash(String publicKeyHash) {
		this.publicKeyHash = publicKeyHash;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKeyHash = Hashing.sha256().hashString(Keys.publicKeyToString(publicKey), StandardCharsets.UTF_8).toString();
	}

	public void setSignature(String signature) {
		this.signature = signature;
	}

	@Override
	public String toString() {
		JSONObject o = new JSONObject();
		o.accumulate("private", privateData);
		o.accumulate("k", publicKeyHash);
		o.accumulate("s", signature);
		return o.toString();
	}

}


