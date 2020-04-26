https://www.wst.space/ssl-part-3-certificate-authority/

Encoding-decoding (files)

Hashing (sha-512)

Encryption Encryption is also a two way process, but original data can be retrieved if and only if the encryption key is known. Here, the word CRYPTO is called Plaintext, the output FUBSWR is called the Ciphertext, the value +3 is called the Encryption key (symmetric key) and the whole process is a cipher. Anyone who knows the encryption key and can apply the reverse of Caesar’s algorithm and retrieve the original Plaintext. Hence it is called a Symmetric Encryption. Nowadays, there are complex algorithms such as AES (Advanced Encryption Standard) and 3DES (Triple Data Encryption Algorithm). This is the encryption technique used in SSL/TLS while sending and receiving data. But, the client and server needs to agree upon a key and exchange it before starting to encrypt the data, right? The initial step of exchanging the key will obviously be in plain text. What if the attacker captures the key while sharing it?

Asymmetric encryption and the algorithm was known as Diffie–Hellman key exchange. Then in 1978, Ron Rivest, Adi Shamir and Leonard Adleman of MIT published the RSA algorithm. in Asymmetric encryption, there will be two keys instead of one. One is called the Public key, and the other one is the Private key. Theoretically, during initiation we can generate the Public-Private key pair to our machine. Private key should  be kept in a safe place and it should never be shared with anyone. Public key, as the name indicates, can be shared with anyone who wish to send encrypted text to you. Now, those who have your public key can encrypt the secret data with it. If the key pair were generated using RSA algorithm, then they should use the same algorithm while encrypting the data. Usually the algorithm will be specified in the public key. The encrypted data can only be decrypted with the private key which is owned by you. Asymmetric encryption is also known as Public Key Infrastructure a.k.a PKI
the user will feel more wait time, and the browser will start to eat the CPU. So PKI is used only to exchange the symmetric key between the client and server. Thereafter symmetric key encryption comes into play and further data transmission makes use of this technique

Agreeing upon a single secret key and sharing it between the client and server is called the Handshake, and it is the first step in TLS. During the time of writing this post TLS 1.2 is the commonly used standard and RSA, Diffie-Hellman key exchange ,ECDH(Elliptic Curve Diffie-Hellman), SRP(Secure Remote Password), PSK(Pre Shared Key) are the key exchange algorithms supported by TLS 1.2.

Man in the middle? Gives their key instead of the intended resource. The answer to the problem is CA (Certificate Authority). In simple terms, Certificate Authority was specified by X.509 standard to ensure the data integrity. Data integrity ensures that the data in transit is not tampered by a third party entity. In other words, the CA act as a middle man between your browser and the server. It’s the CA’s job to ensure data integrity.

The solution is Certificate Authority. When we install our browser or OS it will be shipped with a set of Certificate Authorities. One such example is DigiCert. When I say DigiCert is shipped with the browser, it means that the browser has the Public key of DigiCert. Websites can request certificates and signature from DigiCert. So DigiCert will do a Cryptographic signature on the server certificate with DigiCerts private key. The server will be sending this certificate embedded with its public key when we initiate a connection. Since the browser has the public key of DigiCert, it can verify DigiCert’s signature on the server certificate. And so, the public key of server which is written on the certificate is also trusted.

We know that PKI is used to exchange the session key in TLS protocol. This process can be called as the authentication process. In order to carry out the authentication process, the server needs to send the public key with client. But an intermediate attacker can grab this public key and replace it with his own public key. That is dangerous, because the client will never know the public key was tampered during transit. The client would unknowingly encrypt the symmetric key with public key of the attacker and forward it. Since the attacker holds the corresponding private key, he can decrypt it and steal the data.

In order for the client to trust the Public key being received, concept of CA was introduced. The working of CA is as follows. Imagine that the server https://example.com needs a TLS certificate.

Server example.com will request a TLS certificate from a CA. For example Digicert.
Digicert will create a certificate for example.com. The certificate will contain the necessary data such as the server name, public key of the server etc.
Digicert will create a hash of the data(certificate) and encrypt it with their own private key.  
Browsers and OS comes shipped with the public key of Authorities such as Digicert.
When the browser receives the signed certificate, it will use the public key to generate the hash from the signature. It will also generate the hash of the data(certificate) with the hashing algorithm specified in the certificate. If both the hashes match, signature verification is success and the certificate is trusted.
Now browser can continue to the authentication process with the public key of example.com specified in the certificate.
Here, we can call Digicert a Root CA. 

To bypass the above mechanism, the attacker would need to make the signature match with the data. In order to do that he need to have the private key of Digicert (who originally issued and signed the certificate for example.com). Attacker would fail at this point since the only signature he can create is from his private key. This will not be trusted by our browser. The browser’s certificate store will not have the attacker’s public key and it will show a certificate exception when such an attack occurs such as shown below.

You would have probably noticed this while trying to set up proxies for your browser. Privacy error happens because the proxy tool acts as a man in the middle and displays its own certificate to the browser. If you trust the certificate, then you can either click proceed by showing your trust. Or you can download the certificate of proxy tool and add it to the trusted authorities list inside your browser. That way, you can see the encrypted data in plain text inside the proxy tool.

RSA will hash the certificate before signing it. There is a significant reason for that. If you understand the algorithm in depth, you will know that RSA cannot encrypt the data if the length of data is longer than its key length. Suppose we use a 2048 bit key for encryption, then the certificate data should not exceed 2048 bit a.k.a 255 bytes. This isn’t always feasible, since the certificate contains so many information. So before encryption, a hash function is applied over the certificate which generates a unique random string of specified length. In case of example.com, SHA-256 hashing algorithm is used for this. You can research more on this limitation of RSA if you are interested

During signature verification, browser first verify the digital signature of intermediate certificate using the public key of root CA, which is already stored in the browser. If it is succeeded, browser can now trust the Intermediate certificate and its Public key. Now using this public key, browser will verify the signature of original server certificate. Organization can register as an intermediate CA to sign certificates for their domain. One such example is Google.

DNS translates domain name to IP. IP resolution.

The TLS handshake is divided into various steps as follows
Client Hello
Server Hello
Sharing the certificate and server key exchange
Change cipher spec
Encrypted handshake


CLIENT HELLO: We know that TLS is a protocol implemented above TCP. TLS itself is layer and the bottom layer is called the Record protocol. That means all the data are considered as records. Over the wire, a typical record format would look like:

HH V1:V2 L1:L2 data
HH is a single byte which indicates the type of data in the record. Four types are defined: change_cipher_spec (20), alert (21), handshake (22) and application_data (23).
V1:V2 is the protocol version, over two bytes. For all versions currently defined, V1 has value 0x03, while V2 has value 0x00 for SSLv3, 0x01 for TLS 1.0, 0x02 for TLS 1.1 and 0x03 for TLS 1.2.
L1:L2 is the length of data, in bytes (big-endian convention is used: the length is 256*L1+L2). The total length of data cannot exceed 18432 bytes, but in practice it cannot even reach that value.

The following details are shared with the server by the browser.
Client version
A list of client supported protocol versions in the order of preference. The prefered one is the maximum protocol version that the client wishes to support.
Client random
A 32 byte data in which first 4 bytes represent the current datetime in epoch format. For those who don’t know what is epoch time, it is the number of seconds since January 1, 1970. The rest 28 bytes are generated by a cryptographically strong random number generator(For example, /dev/urandom in Linux). The client random will be used later. For now, just keep it in mind.
Session ID
This field will remain null if the client is connecting to server for the first time. In the above image, you can see that a session id is being sent to the server. This happens because I have previously connected to github.com via https. During that time server will map the symmetric key with session id and store the session id in client browser. A time limit will be set for the mapping. If the browser connects to the same server in future (of course before the time limit is expired) it will send the session id. Server will validate it towards the mapped session and resume the session with previously used symmetric key. In that case, a full handshake is not necessary.
Cipher suites
The client will also send the list of cipher suites which are known to it. The cipher suites are arranged in the order of preference by the client. But it is completely up to the server to follow the order. There is a standard format for cipher suites used in TLS.
Let’s take an example from the list and analyse.
Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 (0xc02b)
TLS: It simply means the protocol which is TLS
ECDHE: It is the key exchange algorithm.
ECDSA: Signing or the authentication algorithm
AES_128_GCM: It is called the bulk encryption algorithm. The symmetric key encryption algorithm is AES with key of length 128 bit. AES is a block cipher, meaning the input plain text is encrypted in block of fixed length. Each block after encryption is sent in sequence and decrypted in a similar fashion. As per standard a block is AES is fixed to 128 bits. But the input plaintext need not be always a multiple of 128. So we might want to add padding to the last block in order to fix it to 128 bits. Apart from that, to improve entropy some random bits are usually added to the plaintext before encryption. It is called the Initialisation Vector (IV). There are many algorithms to add IV and implement padding on the blocks. In our example Galois/Counter Mode (GCM) is used. Probably it isn’t a good idea to explain GCM mode in detail and make things complex.
SHA256: The Message Authentication Code (MAC) algorithm. We will talk about MAC in detail.
Compression methods
In order to reduce the bandwidth compression can be used. But there were successful attacks on TLS in which parameters that are sent with HTTP headers can be captured when compression is used. Cookies can be hijacked with this attack and the vulnerability was termed CRIME. As of TLS 1.3, TLS compression is disabled by the protocol.
Extension
Additional parameters such as server name, padding, supported signing algorithms, etc can be specified as extensions. Feel free to do a research on the contents specified as extensions.
These are the parts of a Client Hello. It is followed by an acknowledgement from server if it has received the Client Hello. Then the server will send Server Hello.

SERVER HELLO 
After receiving the Client Hello server has to send the Server Hello message. The server will check the conditions specified the the Client Hello such as TLS version and algorithms. If all the conditions are acceptable and supported by the server, it will send its certificate along with other details. Otherwise the server will send a handshake failure message.
Server Version
Server will choose the TLS version specified by the client if it can support it. Here TLS 1.2 is chosen
Server Random
Similar to the client random, the server random will also be of 32 byte length. First 4 bytes represent server’s Unix epoch time followed by the 28 byte random number. The client and server randoms will be used to create the encryption key which we will explain later.
Cipher suites
Remember we have sent the sent the supported cipher suites to github.com in the Client Hello? Github picked up the first one from the list. I.e.,
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
Session id
Server store the agreed session parameters in a TLS cache and generate the session id corresponding to it. It is sent to the client along with the Server Hello. Client can key the agreed parameters with this session id. There will be an expiry defined for this. Client will include this id in the Client Hello. If the client connects again to the server before this expiry, server can check for the cached parameters corresponding to the session id and reuse them without the need of a full handshake. This is highly useful since both the server and client can save a lot of computational cost.
There is a downside for this approach when in comes to applications with huge traffic such as Amazon and Google. There will me millions of people connecting to the server each day and server has to keep a TLS cache of all of their session parameters with the session key. This is a huge overhead. In order to solve the issue concept of Session Tickets were introduced. Here, client can specify in the client hello if it supports session tickets. Then, server will create a New Session Ticket and encrypt the session parameters with a private key which is known only to the server. This will be stored on the client and hence all the session data is stored only on the client machine. The ticket is still safe since the key is known only to the server. This data can is included in the Client Hello as an extension named SessionTicket. 
The Server Certificate Message
In our case, the certificate message is 3080 bytes long. There’s no wonder it is the server certificate with all the information. The server sends a complete list of certificate in the order of chain of trust. First one of this chain is the server’s certificate followed by the certificate of the Intermediate CA who issued the server certificate. Then the certificate of next intermediate CA and it continues until the certificate of root CA. The server has the provision to not send the certificate of Root CA since the browser, in most cases, can identify the Root CA from any of the intermediate CA.
Contents of a certificate.
Version and Serial Number
Version represents which version of X.509 standard is used. X.509 is the standard used to define the format of public key certificates. There are 3 versions for X.509 and github uses version 3, the latest one.
From RFC 5280, the serial number MUST be a positive integer assigned by the CA to each certificate. It MUST be unique for each certificate issued by a given CA (i.e., the issuer name and serial number identify a unique certificate). CAs MUST force the serialNumber to be a non-negative integer.
Certificate Signature Algorithm and Value
The browser need to know the algorithm of signature in order to verify the signature. If it is signed with RSA, then the same algorithm is necessary to verify the signature. For Github, PKCS #1 SHA-256 With RSA Encryption is used. Which means SHA-256 is used to generate the hash and RSA is used for signing it.
From our last article, the certificate data is hashed with SHA-256 algorithm and this hash is signed with the private key of Github using RSA encryption.
Issuer
This field holds the details of the authority who issued the certificate. Certificates for Github are issued by Digicert’s intermediate CA.
Validity
This field has two values Not Before and Not After. The values are self explanatory. Certificate is invalid if the current datetime is not between these values. Browser will not trust that certificate.
Subject Public Key Info
This field carries the Public key and the algorithm used to generate the public key. This Key is used to exchange keys which we will discuss later.
Fingerprints
There are two fingerprints SHA 1 and SHA-256 and both of them are generated by the browser and is never sent to the server. These Fingerprints are generated by hashing the DER format of certificate with SHA 1 and SHA-256 functions respectively. We can verify this by downloading the certificate to our machine and applying the Hash function.

SERVER KEY EXCHANGE
Followed by the Server Hello and Certificate message there is optional Server Key Exchange. This message is sent only if the certificate provided by the server is not sufficient to allow the client to exchange a pre-master secret. Let’s see why github.com had to send a Server Key Exchange message.
We have seen that github.com preferred the ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 for the session. Which means Elliptic Curve Diffie Hellman algorithm is used by the parties to exchange the key. In Diffie-Hellman, the client can’t compute a Pre-master secret on its own; both sides contribute to computing it, so the client needs to get a Diffie-Hellman public key from the server. (Don’t get confused about the term Pre-Master Secret, we will discuss about it deeply below.) When using Elliptic Curve Diffie-Hellman, that public key isn’t in the certificate. So the server has to send the client its DH public key in a separate message so that the client can compute the premaster secret. This can be seen in the above image. Note that this key exchange is also secured by a signature (same as certificates, see certificates and https://ldapwiki.com/wiki/ServerKeyExchange).
Once the Server Key Exchange is complete, server will send the Server Hello Done message. Client will start to compute the Pre-Master Secret. Let’s see how.

How to compute the Pre-Master Secret
The Pre-Master Secret computation depends on the type of key exchange algorithm agreed upon. When using RSA for key exchange, the Pre-Master secret is computed from the client side, i.e., the browser. The client generates the 48-byte premaster secret by concatenating the protocol version (2 bytes) and some bytes that the client generates randomly (46 bytes). The client is supposed to get these 46 bytes from a cryptographically secure Pseudo Random Number Generator(PRNG). In practice, this means using the PRNG offered by the operating system such as /dev/urandom. Then this Pre-Master secret is encrypted with server’s public and shared, so that the server can later use this to create the Master Secret.
But, in case of Github, as explained above Diffie-Hellman algorithm is used for key exchange. Things are little different here. The server instantly generates a pair of DH private-public keys. The public key is then shared with the client. This is the Server Key Exchange message as explained above. In response, client will also create a DH key pair and share the public key with server through the Client Key Exchange message as shown below.
You can see the client public key being shared. Now, if you understood the working of Diffie-Hellman algorithm you know that the client and server can reach on a common key from these shared public keys. The newly generated key is called the Pre-Master key.
There is an advantage of using Diffie Hellman algorithm for TLS key exchange. Both the client and server generate a new key pair for each fresh session. And the private keys of both client and server will be deleted immediately once the Pre-Master secret is computed. That means the private key can never be stolen afterwards ensuring perfect forward secrecy.

Client Key Exchange
We already discussed above that the client’s DH public key is shared to the server via the Client Key Exchange message. But if RSA was used, then the client will compute the Pre-Master secret by its own as described above, encrypt it with Server’s public key (RSA public key) and send it back to the server through the Client Key Exchange message. Server can then decrypt it with its private key. Whatever algorithm be, at this point, both the client and server have reached on a common Pre-Master secret. Once this is complete client will send the Change Cipher Spec message

How to compute the Master Secret
What all random data do the client and server have now? The Pre-Master secret and the random values shared by the client and server during the Hello message (remember?) Both the parties will compute Master Secret using these values using a PRF (Pseudo Random Function). According to RFC 5346,
master_secret = PRF(pre_master_secret, "master secret", ClientHello.random + ServerHello.random) [0..47];
Where,
pre_master_secret – The 48 byte Pre-Master secret computed by both parties.
“master secret” – It is simply a string whose ASCII bytes are used.
ClientHello.random – The random value shared in client hello
ServerHello.random – Random value shared in server hello.
The size of Master secret will be always 48 bytes long. Well, no more confusions so far. Both the parties can use the Master secret to encrypt the data and sent them back and forth. Agree, but the procedures are not over yet. Do you think using the same key on both sides is a good idea? Of course not! TLS uses separate keys for client and server and both of them are derived from the Master secret itself. On other words, Master secret is not directly used to encrypt data. Instead separate encryption keys are used for client and server. Since both parties will have both keys, the data encrypted by server with its key can be decrypted by client with ease and vice versa.
It is not over. TLS have additional security mechanism for symmetric key encryption.

Message Authentication Code (MAC) and TLS Data Integrity
There are two possible attacks an eavesdropper can perform on encrypted data in transit. Either try to decrypt the data or try to modify it. As long as the key as secure, we assume decryption is nearly impossible. But what about data modification? How the client and server know that the received data is not modified by an attacker? As said, TLS does more than just encrypting data. TLS also protects the data from undetected modification. On other words we can say TLS checks for data integrity also. Let’s see how it is done.
When the server or client encrypt the data with Master Secret, it also computes a checksum(hash) of the plain data. This checksum is called Message Authentication Code(MAC). The MAC is then included in the encrypted record before sending it. A key is used to generate the MAC from the record in order to ensure that the attacker in transit cannot generate the same MAC from the record. Hence the MAC is called an HMAC(Hashed Message Authentication Code). The other end, upon receiving the message, the decrypter will separate the MAC from the plain text and computes the checksum of the plain text with it’s key and compares it with the received MAC. If a match is found, then we can conclude that the data is not tampered in transit.
It is necessary to have the Client and server to use the same hashing algorithm to create and verify the MAC. Remember the last part of the ciphersuite that Github agreed upon?  
TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256. I.e., SHA256 is the hash function used to process HMAC. To improve the security seperate MAC keys are used by the client and server. Let’s see what all are those.

MAC Keys and IV keys
As per the spec, there are 4 keys used to encrypt and verify the integrity of each message. They are,
Client write encryption key: Used by client to encrypt data and server to decrypt data.
Server write encryption key: Used by server to encrypt data and client to decrypt data.
Client write MAC key: Used by client to create MAC and server to verify MAC.
Server write MAC key: Used by server to create MAC and client to verify MAC.
These key blocks are again generated by the same PRF on the master-key over and over until enough bytes have been created for the keys.
key_block = PRF(SecurityParameters.master_secret, "key expansion", SecurityParameters.server_random + SecurityParameters.client_random);
As you can see, along with the client-server random values and the string “key expansion”, the master secret is also used to increase the entropy of the keys. The PRF can generate keys of arbitrary length. This is useful since the different hash functions have different length by default. In our case SHA256 is used which is 256 bits. But MD5 is used the default length becomes 128 bits.
Apart from this, we know that we are using AES with GCM algorithms, which is a block cipher and it requires a set of bits to use as Initialisation Vector(IV). While discussing ciphersuites we have mentioned that IV is used to improve the entropy of AES encryption. In other words IV helps to generate different ciphertext when the same file is encrypted multiple times. These random bytes are also generated by the same PRF and are termed as client write IV and server write IV. The terminologies are self explanatory. I haven’t researched more on the details of IV because it is a huge topic and beyond the scope of this article.

Generating test data
Both parties have the encryption keys and we are ready to encrypt. But before taking TLS to application layer, like every process, we need to test and verify that the client encrypted data can be decrypted by server and vice versa. In order to do that the client will compute a 12 byte verify_data using the pseudo-random function (PRF) as follows.
verify_data = PRF(master_secret, "client finished", MD5(handshake_messages) + SHA-1(handshake_messages) ) [12]
Where handshake_messages is the buffer of all the handshake messages. The above is true for TLS until version 1.2. There are slight changes from version 1.2. i.e., length of verify_data depends on the cipher suite and it is not always 12. Any cipher suite which does not explicitly specify verify_data_length has a verify_data_length equal to 12. Also, the MD5/SHA-1 combination in the pseudorandom function (PRF) has been replaced with cipher-suite-specified PRFs. So as per latest spec,
Verify_data = PRF(master_secret, finished_label, Hash(handshake_messages)) [0..verify_data_length-1];
So we have the test data, keys and algorithm to encrypt the test data. All the client have to do is encrypt the test data with AES with the client encryption key (or simply, the client write key). An HMAC is also produced as explained above. Client take the result and add a record header byte “0x14” to indicate “finished” and sends it to the server via the Client Finished message. This is the first message protected by the algorithms and keys negotiated between the entities and the last handshake message sent by the client. Since the message is completely encrypted, WireShark will only see the encrypted content and it calls the Finished handshake by the name Encrypted Handshake Message as follows.

Verifying the negotiation
The server does almost the same thing. It sends out a Change Cipher Spec and then a Finished Message that includes all handshake messages. The Change Cipher Spec message marks the point at which the server switches to the newly negotiated cipher suite and keys. The subsequent records from the client will then be encrypted. Along with that, the server Finished Message will contain the decrypted version of the client’s Finished Message. Once the client receive this data, it will decrypt it with the server write key. Consequently, this proves to the client that the server was able to successfully decrypt our message. Kaboom! We are done with the TLS handshake.
All the encryption will be based on the negotiated algorithm. In our case the algorithm was AES_128_GCM. There is no point in explain it in depth here, because when it comes to some other website the algorithm specified by that server will be different. If you are interested in knowing how each of these algorithms work wikipedia has a list of them. I am also learning Cryptography through TLS basics.
