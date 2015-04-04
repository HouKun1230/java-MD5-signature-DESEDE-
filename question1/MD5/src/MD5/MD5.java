package MD5;

import java.security.MessageDigest;

public class MD5 {

	 public static void main(String[] args)throws Exception
	    {
	    	String password = "We have learnt JCA (Java Cryptography Architecture) which is guided by two principles: 1. algorithm independence and extensibility. 2. implementation independence and interoperability. The aim of the JCA is to let API users use cryptographic services without concern for the implementations or even the algorithms being used to implement these services.";
	 
	        MessageDigest md = MessageDigest.getInstance("MD5");
	        md.update(password.getBytes());
	 
	        byte byteData[] = md.digest();
	 
	        StringBuffer hexString = new StringBuffer();
	    	for (int i=0;i<byteData.length;i++) {
	    		String hex=Integer.toHexString(0xff & byteData[i]);
	   	     	if(hex.length()==1) hexString.append('0');
	   	     	hexString.append(hex);
	    	}
	    	System.out.println("Digest(in hex format):: " + hexString.toString());
	    }
	
}
