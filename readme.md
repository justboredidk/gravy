**Gravy Encrypted Chat Program**

This program allows you send messages over a websockets connection, allowing for encrypted p2p messaging without having to deal with nat traversal.
Currently it supports using cloudflare quick tunneling if you provide the cloudflared.exe file. This will give you a temporary URl to share out of band with contacts.
Contacts have a long term ed25519 public key that they share with you in order to authenticate the connection.
The program will automatically generate a keypair and secure the file with a password. (scrypt derivation)
You can host a server and have people connect to you, or connect to someone elses server. The server supports multiple clients, and at the same time, you can connect to multiple servers.

**Protocol**

In order to initiate a connection, the client will send its x25519 public key to the server, who sends its x25519 key back.
After this, the server and client each compute a signature of the x25519 key they recieved, their x25519 key, and a random number. They send this signature and the randome number.
After recieving the signature from the peer, the program will authenticate the identity of the peer using the signature. After this, the encryption keys are dervived.
The protol utilizes seperate racheting send and recieve chains, and will desynchronize if messages are sent out of order.
Additionally, messages are timestamp for a better UX.

I hope to add transmitting files via the program at some point.

**Usage**

Disclaimer: So far, I have only used this on windows, so it might require adjustments, or it might just not work.

To use this program, you will need to run:
```console
pip install -r requirements.txt
```
to install the packages used for this project.

If you would like to create tunnel with cloudflared visit [this](https://developers.cloudflare.com/cloudflare-one/networks/connectors/cloudflare-tunnel/downloads/) url and put the .exe file under resources

**If the program crashes while cloudflared is running, you will have to open task manager and manually exit**

Then run the cfchatgui python file to start the program. Make an account and login. Upon login, you will be on the dashboard. This is where you manage the account.
You can copy your public key here, and add/remove contacts by putting in your nickname for them and their public key.
If you select a contact you can open their history as a sidebar tab, or delete it altogether.

To test out the program, copy your public key and paste it into a contact, naming it whatever you want. Now you can connect to yourself!
Click on the "Server" button in the sidebar. Type in port "8080" and select "No Tunnel". Click "Start Server". Now your server is running.
In the "Server Manager" tab, copy the url it gives you
```console
ws://localhost:8080
```

Next, click on the "Connect" button in the sidebare and paste in the URL. Click on the contact you created for yourself to populate the name and ID fields.
Click "Connect to Server". A tab should appear in the sidebar, and you should be facing a message client. Try sending some messages.
If you go back to the server page, a new tab should have opened containing your contact's name. If you navigate to it, all the message you sent should appear.

You can kick clients within their tab or from the "Server Manager" page. As a client you can disconnect by clicking "Exit Session"
