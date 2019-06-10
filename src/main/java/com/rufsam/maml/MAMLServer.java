package com.rufsam.maml;

import jota.utils.InputValidator;

import static spark.Spark.get;

public class MAMLServer {

    public static void main(String[] args) {

        if(args.length >= 5) {
            MAML.protocol = args[0];
            MAML.host = args[1];
            MAML.port = args[2];
            MAML.depth = Integer.parseInt(args[3]);
            MAML.minWeightMagnitude = Integer.parseInt(args[4]);
        }

        get("/read/:address", (request, response) -> {
            String address = request.params(":address");
            if(!InputValidator.isAddress(address))
                return "{\"message\": \"invalid address provided\"}";
            MAML maml = new MAML(address);
            MessageResponse r = maml.read();
            if(r == null )
                return "{}";
            return r;
        });

        get("/read/:address/:password", (request, response) -> {
            String address = request.params(":address");
            String password = request.params(":password");
            if(!InputValidator.isAddress(address))
                return "{\"message\": \"invalid address provided\"}";
            MAML maml = new MAML(address, password);
            MessageResponse r = maml.read();
            if(r == null )
                return "{}";
            return r;
        });

    }

}