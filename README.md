# MAM Lite - a more flexible messaging protocol for IOTA

MAM Lite (MAML) is a  lightweight, flexible and easy to use protocol which ensures privacy and integrity for data communication at another level. More information about MAML can be found here: https://medium.com/@samuel.rufinatscha/mam-lite-a-more-flexible-messaging-protocol-for-iota-562fdd318e1d

Features
- Authentication
- Forward Secrecy
- Spam protection
- Stream access from every address
- Channel splitting
- Multipart messages
- Different encryption modes (AES and public key encryption for fine grained access)

MAM Lite is a work in progress. I have designed the library to be as easy to use as possible. If you have any questions, I'm happy to answer them. You can find me on Discord (Samuel Rufinatscha#2769) or you can send me an email at samuel.rufinatscha@gmail.com

## Console App

To play with the command line app, Java 8 must be installed.
You can get it here: https://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html

After you have successfully installed Java, download the latest maml.jar file: https://github.com/rufsam/maml/releases/tag/maml.jar

Open a console/terminal, navigate to it and start it with:

```js
java -jar maml.jar
```
If you want to pass a node manually, run it as follows:
#### Syntax: protocol, host, port, depth, minWeightMagnitude
```js
java -jar maml.jar https nodes.thetangle.org 443 3 14
```


## How to use the library

Every author of a message does need a RSA key pair. This can be created easily by the provided crypto classes:

```js
KeyPair keys = RSA.generateKeyPair();
PublicKey publicKey = keys.getPublic();
PrivateKey privateKey = keys.getPrivate();
```

A stream can be initialized as follows:

```js
MAML m = new MAML(address);
```
if it's password protected:
```js
MAML m = new MAML(address, password);
```
Publish a message:

```js    
Message msg = new Message();
msg.setPrivateData("This is my message!");
msg.setPublicKey(publicKey);
m.write(msg, privateKey);
```

Read a message:

```js
MessageResponse msg = m.read();
```

To split a channel, you simply need to change the password. The rest will be done automatically:

```js
String nextAddress = m.split(newPassword);
```

To trust messages only from a specific set of users, put the appropriate public keys in the keystore:

```js
m.addTrustedAuthor(publicKeyOfBob);
m.addTrustedAuthor(publicKeyOfAlice);
...
```

## How to use MAML in server mode

To use MAML in server mode, Java 8 must be installed.
You can get it here: https://www.oracle.com/technetwork/java/javase/downloads/jre8-downloads-2133155.html

After you have successfully installed Java, download the latest maml.server.jar file: https://github.com/rufsam/maml/releases/tag/maml.server.jar

Open a console/terminal, navigate to it and start it with:

```js
java -jar maml.server.jar
```
If you want to pass a node manually, run it as follows:
#### Syntax: protocol, host, port, depth, minWeightMagnitude
```js
java -jar maml.server.jar http localhost 80 3 14
```


### Access the REST API as follows:

Read a message:
```js
http://localhost:4567/read/YOUR_ADDRESS
```
If the message is password protected:
```js
http://localhost:4567/read/YOUR_ADDRESS/PASSWORD
```
