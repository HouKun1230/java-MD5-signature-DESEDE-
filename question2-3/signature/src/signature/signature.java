package signature;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;  

public class signature {

	public static void main(String[] args) throws NoSuchAlgorithmException, FileNotFoundException, IOException  {  
	    signature my=new signature();  
	    my.myDigest();  
	    KeyPairGenerator keygen = java.security.KeyPairGenerator.getInstance("DSA");
	    SecureRandom secrand=new SecureRandom();  
	    secrand.setSeed("tttt".getBytes()); 
	    keygen.initialize(512,secrand);      
	    keygen.initialize(512);  
	    KeyPair keys=keygen.generateKeyPair();
	    PublicKey pubkey=keys.getPublic();  
	    PrivateKey prikey=keys.getPrivate();  
	    java.io.ObjectOutputStream out=new java.io.ObjectOutputStream(new java.io.FileOutputStream("myprikey.dat"));  
	     out.writeObject(prikey);  
	     out.close();  
	     out=new java.io.ObjectOutputStream(new java.io.FileOutputStream("mypubkey.dat"));  
	     out.writeObject(pubkey);  
	     out.close(); 
	  }  
	  public void myDigest()  
	  {  
	   try {  
	     String myinfo="We have learnt JCA (Java Cryptography Architecture) which is guided by two principles: 1. algorithm independence and extensibility. 2. implementation independence and interoperability. The aim of the JCA is to let API users use cryptographic services without concern for the implementations or even the algorithms being used to implement these services.";  
	      java.security.MessageDigest alga=java.security.MessageDigest.getInstance("SHA-1");  
	      alga.update(myinfo.getBytes());  
	      byte[] digesta=alga.digest();  
	      System.out.println("signature:"+byte2hex(digesta));  
	      //(myinfo)(digesta)   
	      java.security.MessageDigest algb=java.security.MessageDigest.getInstance("SHA-1");  
	      algb.update(myinfo.getBytes());  
	      if (algb.isEqual(digesta,algb.digest())) {  
	         System.out.println("");  
	       }  
	       else  
	        {  
	          System.out.println("");  
	         }  
	   }  
	   catch (java.security.NoSuchAlgorithmException ex) {  
	     System.out.println("");  
	   }  
	  }  
	  public String byte2hex(byte[] b) //  
	    {  
	     String hs="";  
	     String stmp="";  
	     for (int n=0;n<b.length;n++)  
	      {  
	       stmp=(java.lang.Integer.toHexString(b[n] & 0XFF));  
	       if (stmp.length()==1) hs=hs+"0"+stmp;  
	       else hs=hs+stmp;  
	       if (n<b.length-1)  hs=hs+":";  
	      }  
	     return hs.toUpperCase();  
	    }  
	}  
	

