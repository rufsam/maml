package com.rufsam.maml;

import com.rufsam.maml.crypto.RSA;

import java.security.KeyPair;
import java.util.Scanner;

public class ConsoleApp {

	public static void main(String[] args) throws Exception {
		
		if(args.length >= 5) {
			MAML.protocol = args[0];
			MAML.host = args[1];
			MAML.port = args[2];
			MAML.depth = Integer.parseInt(args[3]);
			MAML.minWeightMagnitude = Integer.parseInt(args[4]);
		}
		
		System.out.println("MAM Lite 1.3.2\n");
		
		Scanner in = new Scanner(System.in);
		
		System.out.print("Enter channel id: ");
		String channelID = in.nextLine();
		System.out.print("Enter channel password: ");
		String password = in.nextLine();

		String mamChannel = MAML.hash(channelID+password);
		System.out.println("CHANNEL START: "+mamChannel);
		
		KeyPair keys = RSA.generateKeyPair();

		MAML m = new MAML(mamChannel, password);
		
		System.out.println("\nEnter your command. Enter 'help' for help.");
		System.out.print("> ");
		
		do {
			
			switch (in.nextLine().trim()) {
			
			case "read": {
				try {
					MessageResponse r = m.read();
					if(r != null)
						System.out.println(r.getAddress() + " -> " + (r.getMessage() == null? "unable to read content" : r));
					else
						System.out.println("null");
				} catch(Exception e) {
					e.printStackTrace();
				}
				System.out.print("> ");
				break;
			}

			case "write": {
				System.out.print("Enter data: ");
				String pData = in.nextLine();
				Message msg = new Message();
				msg.setPrivateData(pData);
				msg.setPublicKey(keys.getPublic());
				MessageResponse r = m.write(msg, keys.getPrivate());
				if(r != null)
					System.out.println(r.getAddress() + " -> " + r);
				else
					System.out.println("null");
				System.out.print("> ");
				break;
			}
			
			case "split": {
				System.out.print("Enter new channel password: ");
				String key = in.nextLine();
				m.split(key);
				System.out.println("Password set.");
				System.out.print("> ");
				break;
			}

			case "help": {
				System.out.println("Following commands are supported:\nread\nwrite\nsplit");
				System.out.print("> ");
				break;
			}

			default:
				System.out.print("> ");
				break;
			}

		} while(true);

	}

}