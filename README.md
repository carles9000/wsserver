# Harbour websocket ssl server

This version is a fork of the websockets prototype from https://github.com/FiveTechSoft/wsserver adapted for use with SSL

Basically this server allows you to communicate between a web browser and a Harbour app (no matter where it is!), using websockets and certificates to be able to run it under SSL.

In this version the websocket server implements an echo service, just to check that it properly works. It sends you back whatever you may send to it.
You can easily change its source code to implement any other conversation you may have in mind. 

## How to test it:

SSL VERSION
- Compile with go64_ssl.bat
- Use port 443 in client.html example

NO SSL VERSION
- Compile with go64.bat
- Use port 9000 in client.html example

## Example

Run wsserver.exe. It will display all messages that come in. Press esc at any time to end the session.
Drag the client.html example to the browser. Anything you send to the server from the web page will come back to you (it's a kind of karma reminder :-)
Type exit to tell the server to end your session.

## Note

It is very important to have a certificate in order to run the SSL example correctly, otherwise it will not work correctly.
You will have to install the certificates in the /cert folder
- /cert/certificate.pem
- /cert/privatekey.pem 

Enjoy it!

[![](https://github.com/carles9000/wsserver/blob/master/resources/wsserver.gif)](https://github.com/carles9000/wsserver)

<h3><a href="https://harbour.github.io">Harbour Project</a></h3>
