package com.polytech;
import java.security.*;
import javax.crypto.*;

//import sun.security.mscapi.CSignature.SHA1withRSA;

import java.io.*;

public class Entity{

	// keypair
	public PublicKey thePublicKey;
	private PrivateKey thePrivateKey;
	
	/**
	  * Entity Constructor
	  * Public / Private Key generation
	 **/
	public Entity(){
		// INITIALIZATION

		// generate a public/private key
		try{
			// get an instance of KeyPairGenerator  for RSA	
			KeyPairGenerator k1;
			k1=KeyPairGenerator.getInstance("RSA");
			// Initialize the key pair generator for 1024 length
			k1.initialize(1024);
			// Generate the key pair
			KeyPair kp = k1.genKeyPair();

			// save the public/private key
			this.thePublicKey=  kp.getPublic(); 
			this.thePrivateKey = kp.getPrivate();
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
		}
	}


	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] sign(byte[] aMessage){
		
		try{
			// use of java.security.Signature
			Signature obj=Signature.getInstance("SHA1withRSA");
			// Init the signature with the private key
			obj.initSign(thePrivateKey);
			// update the message
			obj.update(aMessage);
			// sign
			return obj.sign();
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean checkSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// use of java.security.Signature
			Signature obj2=Signature.getInstance("SHA1withRSA");
			// init the signature verification with the public key
			obj2.initVerify(aPK);
			// update the message
			obj2.update(aMessage);
			// check the signature
			return obj2.verify(aSignature);
		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}
	
	
	/**
	  * Sign a message
	  * Parameters
	  * aMessage : byte[] to be signed
	  * Result : signature in byte[] 
	  **/
	public byte[] mySign(byte[] aMessage){
		
		try{
			// get an instance of a cipher with RSA with ENCRYPT_MODE
			Cipher c=Cipher.getInstance("RSA");
			// Init the signature with the private key
			c.init(Cipher.ENCRYPT_MODE, thePrivateKey);
			// get an instance of the java.security.MessageDigest with SHA1
			MessageDigest obj3=MessageDigest.getInstance("SHA1");
			// process the digest
			byte[] mgD=obj3.digest(aMessage);
			// return the encrypted digest
			return c.doFinal(mgD);
			
		}catch(Exception e){
			System.out.println("Signature error");
			e.printStackTrace();
			return null;
		}
		
	}
	
	/**
	  * Check aSignature is the signature of aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be signed
	  * aSignature : byte[] associated to the signature
	  * aPK : a public key used for the message signature
	  * Result : signature true or false
	  **/
	public boolean myCheckSignature(byte[] aMessage, byte[] aSignature, PublicKey aPK){
		try{
			// get an instance of a cipher with RSA with ENCRYPT_MODE
			Cipher c=Cipher.getInstance("RSA");
			// Init the signature with the public key
			c.init(Cipher.DECRYPT_MODE, aPK);
			// decrypt the signature
			byte[] signedDigest=c.doFinal(aSignature);
			// get an instance of the java.security.MessageDigest with SHA1
			MessageDigest obj4=MessageDigest.getInstance("SHA1");
			// process the digest
			byte[] mgD=obj4.digest(aMessage);
			// check if digest1 == digest2
			return (mgD.equals(mgD));

		}catch(Exception e){
			System.out.println("Verify signature error");
			e.printStackTrace();
			return false;
		}
	}	
	
	
	/**
	  * Encrypt aMessage with aPK
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * aPK : a public key used for the message encryption
	  * Result : byte[] ciphered message
	  **/
	public byte[] encrypt(byte[] aMessage, PublicKey aPK){
		try{
			// get an instance of RSA Cipher
			Cipher c1=Cipher.getInstance("RSA");
			// init the Cipher in ENCRYPT_MODE and aPK
			c1.init(Cipher.ENCRYPT_MODE, aPK);
			// use doFinal on the byte[] and return the ciphered byte[]
			byte[] result=c1.doFinal(aMessage);
			return result;
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}
	}

	/**
	  * Decrypt aMessage with the entity private key
	  * Parameters
	  * aMessage : byte[] to be encrypted
	  * Result : byte[] deciphered message
	  **/
	public byte[] decrypt(byte[] aMessage){
		try{
			// get an instance of RSA Cipher
			Cipher c1=Cipher.getInstance("RSA");
			// init the Cipher in DECRYPT_MODE and aPK
			c1.init(Cipher.DECRYPT_MODE, thePrivateKey);
			// use doFinal on the byte[] and return the deciphered byte[]
			byte[] result=c1.doFinal(aMessage);
			return result;
			
		}catch(Exception e){
			System.out.println("Encryption error");
			e.printStackTrace();
			return null;
		}

	}




}