package com.rufsam.maml;

import org.json.JSONObject;

public class MessageResponse {

    private String address;
    private String nextAddress;
    private Message message;
    private boolean isValid;
    private boolean isTrusted;


    public MessageResponse(String address, String nextAddress, Message message, boolean isValid, boolean isTrusted) {
        this.address = address;
        this.nextAddress = nextAddress;
        this.message = message;
        this.isValid = isValid;
        this.isTrusted = isTrusted;
    }

    public String getAddress() {
        return address;
    }

    public String getNextAddress() {
        return nextAddress;
    }

    public Message getMessage() {
        return message;
    }

    public boolean isTrusted() { return isTrusted; };

    public boolean isValid() {
        return isValid;
    }

    @Override
    public String toString() {

        JSONObject o = null;

        if(message == null)
            o = new JSONObject();
        else
            o = new JSONObject(getMessage().toString());

        o = o.accumulate("address", address);
        o = o.accumulate("nextAddress", nextAddress);
        o = o.accumulate("isValid", isValid);
        o = o.accumulate("isTrusted", isTrusted);

        return o.toString();

    }

}
