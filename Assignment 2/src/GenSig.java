import java.io.*;
import java.security.*;

class GenSig {

	public static void main(String[] args) {

		/* Generate a RSA signature */

		if (args.length != 1) {
			System.out.println("Usage: GenSig nameOfFileToSign");
		}
		else try{

			/* Generate a key pair */

			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);

			KeyPair pair = keyGen.generateKeyPair();
			PrivateKey priv = pair.getPrivate();
			PublicKey pub = pair.getPublic();


			/* Create a Signature object and initialize it with the private key */

			Signature rsa = Signature.getInstance("MD5withRSA"); 

			rsa.initSign(priv);

			/* Update and sign the data */

			FileInputStream fis = new FileInputStream(args[0]);
			BufferedInputStream bufin = new BufferedInputStream(fis);
			byte[] buffer = new byte[1024];
			int len;
			while (bufin.available() != 0) {
				len = bufin.read(buffer);
				rsa.update(buffer, 0, len);
			};

			bufin.close();

			/* Now that all the data to be signed has been read in, 
                    generate a signature for it */

			byte[] realSig = rsa.sign();


			/* Save the signature in a file */
			FileOutputStream sigfos = new FileOutputStream("signature_file");
			sigfos.write(realSig);

			sigfos.close();


			/* Save the public key in a file */
			byte[] key = pub.getEncoded();
			FileOutputStream keyfos = new FileOutputStream("pub_key");
			keyfos.write(key);

			keyfos.close();

		} catch (Exception e) {
			System.err.println("Caught exception " + e.toString());
		}

	};

}