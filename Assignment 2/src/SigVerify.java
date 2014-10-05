/*Author: Alvin Kang
 * 
 */

import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class SigVerify {

	/**
	 * Command-line program that takes in original data_file, signature_file, key. 
	 * Purpose: Verifies whether the signature_file has the same hash as the data_file.
	 * 
	 * @throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, IOException, InvalidKeySpecException
	 * @param (command-line): data_file, signature_file, key 
	 **/
	
	public static void main(String[] args) throws NoSuchAlgorithmException, 
	InvalidKeyException, SignatureException, IOException, InvalidKeySpecException {

		// Read in the key
		FileInputStream keyfis = new FileInputStream(args[2]);
		byte[] encKey = new byte[keyfis.available()];
		keyfis.read(encKey);
		keyfis.close();

		X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);


		// Read signed_file
		FileInputStream sigfis = new FileInputStream(args[1]);
		byte[] sigToVerify = new byte[sigfis.available()]; 
		sigfis.read(sigToVerify); 
		sigfis.close(); // sigToVerify is the input signature_file


		// Verify signature
		Signature sig = Signature.getInstance("MD5withRSA");
		sig.initVerify(pubKey);

		FileInputStream datafis = new FileInputStream(args[0]);
		BufferedInputStream bufin = new BufferedInputStream(datafis);

		byte[] buffer = new byte[1024];
		int len;
		while (bufin.available() != 0) {
			len = bufin.read(buffer);
			sig.update(buffer, 0, len);
		};

		bufin.close();

		boolean verifies = sig.verify(sigToVerify);
		
		String result = "NO";
		if (verifies) result = "YES";

		// Print verify boolean
		System.out.println("The signature verifies: " + result);
	}

}
