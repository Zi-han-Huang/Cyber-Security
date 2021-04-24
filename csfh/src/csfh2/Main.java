/**
 * 
 */
package csfh2;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

/**
 * @author zh
 *
 */
public class Main {

	/**
	 * @param args
	 */
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		/*
		 * RSA keys
		 */
		PublicKey pk = null;
		PrivateKey sk = null;
		try
		{
			KeyPairGenerator kg = KeyPairGenerator.getInstance("RSA");
			kg.initialize(2048);
			KeyPair kp = kg.generateKeyPair();
			pk = kp.getPublic();
			sk = kp.getPrivate();
		}
		catch(Exception e)
		{
			System.err.println(e.toString());
			System.exit(0);
		}
		System.err.print("RSA public key = ");
		print_bytes(pk.getEncoded());
		System.err.print("RSA secret key = ");
		print_bytes(sk.getEncoded());
		
		/*
		 * RSA encryption
		 */
		byte[] ciphertext = rsa_encdec(Cipher.ENCRYPT_MODE, pk, "Hello World".getBytes());
		System.err.print("ciphertext = ");
		print_bytes(ciphertext);
		byte[] plaintext = rsa_encdec(Cipher.DECRYPT_MODE, sk, ciphertext);
		System.err.println("plaintext = " + new String(plaintext));
	
		/*
		 * Message Digests
		 */
		String mdin = new String("Message Digest long string example, more stuff, and more");
		byte[] digest = null;
		try 
		{
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			//md.update(mdin.getBytes());
			digest = md.digest();
			System.err.print("digest = ");
			print_bytes(digest);
		}
		catch(Exception e)
		{
			System.err.println(e.toString());
			System.exit(0);
		}
		/*
		 * Digital signature of message digest
		 */
		byte[] signature = rsa_encdec(Cipher.ENCRYPT_MODE, sk, digest);
		System.err.print("signature = ");
		print_bytes(signature);
		
		byte[] undosig = rsa_encdec(Cipher.DECRYPT_MODE, pk, signature);
		System.err.print("undosig = ");
		print_bytes(undosig);
		
		if(MessageDigest.isEqual(undosig, digest))
			System.err.println("equal");
		else
			System.err.println("DIFFERENT!!");
	}
	private static byte[] rsa_encdec(int mode, Key key, byte[] bytes) {
		Cipher c = null;
		try
		{
			c = Cipher.getInstance("RSA");
			c.init(mode, key);
			return c.doFinal(bytes);
		}
		catch(Exception e)
		{
			System.err.println(e.toString());
			System.exit(0);
		}
		return null;
	}

	public static void print_bytes(byte[] b)
	{
		System.err.print("[" + b.length + "]");
		for (int i = b.length - 1; i >=0; i--)
		{
			int k = (int) b[i] & 0xff;
			int k1 = k & 0xf;
			int k2 = (k >> 4) & 0xf;
			System.err.print(String.format("%x%x", k1, k2));
		}
		System.err.print("\n");
	}
	
	

}