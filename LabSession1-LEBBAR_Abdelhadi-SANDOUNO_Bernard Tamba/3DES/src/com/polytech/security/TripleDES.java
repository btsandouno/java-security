package com.polytech.security;
import java.io.*;
import javax.crypto.*;
import javax.crypto.spec.*;

//import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.*;
import java.util.*;

public class TripleDES{

static public void main(String[] argv){

// Provider prov = new org.bouncycastle.jce.provider.BouncyCastleProvider();
//Security.addProvider(prov);
try{

if(argv.length>0){
// Create a TripleDES object
TripleDES the3DES = new TripleDES();

if(argv[0].compareTo("-ECB")==0){

// ECB mode
  // encrypt ECB mode
  Vector Parameters=
  the3DES.encryptECB(
  new FileInputStream(new File(argv[1])),   // clear text file
    new FileOutputStream(new File(argv[2])), // file encrypted
    "DES", // KeyGeneratorName
    "DES/ECB/NoPadding"); // CipherName
  // decrypt ECB mode
  the3DES.decryptECB(Parameters, // the 3 DES keys
  new FileInputStream(new File(argv[2])),   // the encrypted file
    new FileOutputStream(new File(argv[3])), // the decrypted file
    "DES/ECB/NoPadding");   // CipherName
}
else if(argv[0].compareTo("-CBC")==0){
// decryption
  // encrypt CBC mode
  Vector Parameters =
  the3DES.encryptCBC(
  new FileInputStream(new File(argv[1])),   // clear text file
    new FileOutputStream(new File(argv[2])), // file encrypted
    "DES", // KeyGeneratorName
  "DES/CBC/NoPadding"); // CipherName
    //"DES/CBC/PKCS5Padding"); // CipherName
  // decrypt CBC mode
  the3DES.decryptCBC(
  Parameters, // the 3 DES keys
  new FileInputStream(new File(argv[2])),   // the encrypted file
  new FileOutputStream(new File(argv[3])), // the decrypted file
  "DES/CBC/NoPadding"); // CipherName
  //"DES/CBC/PKCS5Padding");   // CipherName  
}

}

else{
System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
}
}catch(Exception e){
e.printStackTrace();
System.out.println("java TripleDES -ECB clearTextFile EncryptedFile DecryptedFile");
System.out.println("java TripleDES -CBC clearTextFile EncryptedFile DecryptedFile");
}
}


/**
* 3DES ECB Encryption
*/
private Vector<SecretKey> encryptECB(FileInputStream in,
FileOutputStream out,
String KeyGeneratorInstanceName,
String CipherInstanceName){
try{

// GENERATE 3 DES KEYS
KeyGenerator temp;
temp= KeyGenerator.getInstance(KeyGeneratorInstanceName);
SecretKey K1 = temp.generateKey();
temp= KeyGenerator.getInstance(KeyGeneratorInstanceName);
SecretKey K2 = temp.generateKey();
temp= KeyGenerator.getInstance(KeyGeneratorInstanceName);
SecretKey K3 = temp.generateKey();

// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR ENCRYPTION
// WITH THE FIRST GENERATED DES KEY
Cipher C1 = Cipher.getInstance(CipherInstanceName);
C1.init(Cipher.ENCRYPT_MODE, K1);
// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR DECRYPTION
// WITH THE SECOND GENERATED DES KEY
Cipher C2 = Cipher.getInstance(CipherInstanceName);
C2.init(Cipher.DECRYPT_MODE, K2);
// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR ENCRYPTION
// WITH THE THIRD GENERATED DES KEY
Cipher C3 = Cipher.getInstance(CipherInstanceName);
C3.init(Cipher.ENCRYPT_MODE, K3);

// GET THE MESSAGE TO BE ENCRYPTED FROM IN
byte[] b = new byte[128];
in.read(b);

// CIPHERING    
// CIPHER WITH THE FIRST KEY
byte[] msg1 = C1.doFinal (b);
// DECIPHER WITH THE SECOND KEY
byte[] msg2 = C2.doFinal (msg1);
// CIPHER WITH THE THIRD KEY
byte[] msg3 = C3.doFinal (msg2);
// write encrypted file


// WRITE THE ENCRYPTED DATA IN OUT
out.write(msg3);
// return the DES keys list generated
Vector<SecretKey> E= new Vector<SecretKey>();
E.add(K1);
E.add(K2);
E.add(K3);

return E;

}catch(Exception e){
e.printStackTrace();
return null;
}

}

/**
* 3DES ECB Decryption
*/
private void decryptECB(Vector<SecretKey> Parameters,
FileInputStream in,
FileOutputStream out,
String CipherInstanceName){
try{

// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR DECRYPTION
// WITH THE THIRD GENERATED DES KEY
Cipher C3 = Cipher.getInstance(CipherInstanceName);
C3.init(Cipher.DECRYPT_MODE, Parameters.get(2));
// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR ENCRYPTION
// WITH THE SECOND GENERATED DES KEY
Cipher C2 = Cipher.getInstance(CipherInstanceName);
C2.init(Cipher.ENCRYPT_MODE,Parameters.get(1) );
// CREATE A DES CIPHER OBJECT FOR ENCRYPTION
// WITH CipherInstanceName
// FOR DECRYPTION
// WITH THE FIRST GENERATED DES KEY
Cipher C1 = Cipher.getInstance(CipherInstanceName);
C1.init(Cipher.DECRYPT_MODE, Parameters.get(0));
// GET THE ENCRYPTED DATA FROM IN
byte[] c = new byte[128];
in.read(c);

// DECIPHERING    
// DECIPHER WITH THE THIRD KEY
byte[] msg1 = C3.doFinal (c);
// CIPHER WITH THE SECOND KEY
byte[] msg2 = C2.doFinal (msg1);
// DECIPHER WITH THE FIRST KEY
byte[] msg3 = C1.doFinal (msg2);

// WRITE THE DECRYPTED DATA IN OUT
out.write(msg3);
}catch(Exception e){
e.printStackTrace();
}

}
 
/**
* 3DES CBC Encryption
*/
private Vector encryptCBC(FileInputStream in,
FileOutputStream out,
String KeyGeneratorInstanceName,
String CipherInstanceName){
try{

// GENERATE 3 DES KEYS
	KeyGenerator temp;
	temp= KeyGenerator.getInstance(KeyGeneratorInstanceName);
	SecretKey K1 = temp.generateKey();
	temp= KeyGenerator.getInstance(KeyGeneratorInstanceName);
	SecretKey K2 = temp.generateKey();
	temp= KeyGenerator.getInstance(KeyGeneratorInstanceName);
	SecretKey K3 = temp.generateKey();
// GENERATE THE IV
	IvParameterSpec V1 = new IvParameterSpec(new byte[8]) ;
	IvParameterSpec V2 = new IvParameterSpec(new byte[8]) ;
	IvParameterSpec V3 = new IvParameterSpec(new byte[8]) ;
// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR ENCRYPTION
// WITH THE FIRST GENERATED DES KEY
	Cipher C1 = Cipher.getInstance(CipherInstanceName);
	C1.init(Cipher.ENCRYPT_MODE, K1,V1);
// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR DECRYPTION
// WITH THE SECOND GENERATED DES KEY
	Cipher C2 = Cipher.getInstance(CipherInstanceName);
	C2.init(Cipher.DECRYPT_MODE, K2,V2);
// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR ENCRYPTION
// WITH THE THIRD GENERATED DES KEY
	Cipher C3 = Cipher.getInstance(CipherInstanceName);
	C3.init(Cipher.ENCRYPT_MODE, K3,V3);
// GET THE DATA TO BE ENCRYPTED FROM IN
	byte[] b = new byte[128];
	in.read(b);
// CIPHERING    
// CIPHER WITH THE FIRST KEY
	byte[] msg1 = C1.doFinal (b);
// DECIPHER WITH THE SECOND KEY
	byte[] msg2 = C2.doFinal (msg1);
// CIPHER WITH THE THIRD KEY
	byte[] msg3 = C3.doFinal (msg2);
// WRITE THE ENCRYPTED DATA IN OUT
	out.write(msg3);

// return the DES keys list generated
	Vector E= new Vector();
	E.add(K1);
	E.add(K2);
	E.add(K3);
	E.add(V1);
	E.add(V2);
	E.add(V3);
return E;

}catch(Exception e){
e.printStackTrace();
return null;
}
}

/**
* 3DES CBC Decryption
*/
private void decryptCBC(Vector<SecretKey> Parameters,
FileInputStream in,
FileOutputStream out,
String CipherInstanceName){
try{

// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR DECRYPTION  
// WITH THE THIRD GENERATED DES KEY
	Cipher C3 = Cipher.getInstance(CipherInstanceName);
	C3.init(Cipher.DECRYPT_MODE,(SecretKey) Parameters.get(2),(IvParameterSpec)Parameters.get(5));
// CREATE A DES CIPHER OBJECT
// WITH CipherInstanceName
// FOR ENCRYPTION
// WITH THE SECOND GENERATED DES KEY
	Cipher C2 = Cipher.getInstance(CipherInstanceName);
	C2.init(Cipher.ENCRYPT_MODE,(SecretKey)Parameters.get(1), (IvParameterSpec) Parameters.get(4));
// CREATE A DES CIPHER OBJECT FOR ENCRYPTION
// WITH CipherInstanceName
// FOR DECRYPTION
// WITH THE FIRST GENERATED DES KEY
	Cipher C1 = Cipher.getInstance(CipherInstanceName);
	C1.init(Cipher.DECRYPT_MODE, (SecretKey)Parameters.get(0),(IvParameterSpec) Parameters.get(3));
// GET ENCRYPTED DATA FROM IN
	byte[] b = new byte[128];
	in.read(b);
// DECIPHERING    
// DECIPHER WITH THE THIRD KEY
	byte[] msg1 = C3.doFinal (b);
// CIPHER WITH THE SECOND KEY
	byte[] msg2 = C2.doFinal (msg1);
// DECIPHER WITH THE FIRST KEY
	byte[] msg3 = C1.doFinal (msg2);
// WRITE THE DECRYPTED DATA IN OUT
	out.write(msg3);
}catch(Exception e){
e.printStackTrace();
}

}
 

}