package signature;


import java.security.*;  
import java.security.spec.*; 

public class verify {
	public static void main(String[] args) throws java.security.NoSuchAlgorithmException,java.lang.Exception {  
        verify my=new verify();  
        my.run();  
}
	public void run()
	  {

	   if ((new java.io.File("myprikey.dat")).exists()==false) {
	       if (generatekey()==false) {
	           System.out.println("");
	           return;
	          };
	        }

	  try {
	  java.io.ObjectInputStream in=new java.io.ObjectInputStream(new java.io.FileInputStream("myprikey.dat"));
	  PrivateKey myprikey=(PrivateKey)in.readObject();
	  in.close();

	  String myinfo="We have learnt JCA (Java Cryptography Architecture) which is guided by two principles: 1. algorithm independence and extensibility. 2. implementation independence and interoperability. The aim of the JCA is to let API users use cryptographic services without concern for the implementations or even the algorithms being used to implement these services.";    //

	  java.security.Signature signet=java.security.Signature.getInstance("DSA");
	  signet.initSign(myprikey);
	  signet.update(myinfo.getBytes());
	  byte[] signed=signet.sign();  //
	  System.out.println("signed()="+byte2hex(signed));

	  java.io.ObjectOutputStream out=new java.io.ObjectOutputStream(new java.io.FileOutputStream("myinfo.dat"));
	  out.writeObject(myinfo);
	  out.writeObject(signed);
	  out.close();
	  System.out.println("");
	  }
	  catch (java.lang.Exception e) {
	    e.printStackTrace();
	    System.out.println("");
	  };

	  try {
	   java.io.ObjectInputStream in=new java.io.ObjectInputStream(new java.io.FileInputStream("mypubkey.dat"));
	   PublicKey pubkey=(PublicKey)in.readObject();
	   in.close();
	   System.out.println(pubkey.getFormat());
	   in=new java.io.ObjectInputStream(new java.io.FileInputStream("myinfo.dat"));
	   String info=(String)in.readObject();
	   byte[] signed=(byte[])in.readObject();
	   in.close();
	  java.security.Signature signetcheck=java.security.Signature.getInstance("DSA");
	  signetcheck.initVerify(pubkey);
	  signetcheck.update(info.getBytes());
	  if (signetcheck.verify(signed)) {
	  System.out.println("info="+info);
	   System.out.println("");
	  }
	  else  System.out.println("");
	  }
	  catch (java.lang.Exception e) {e.printStackTrace();};
	  }

	  public boolean generatekey()
	  {
	    try {
	  java.security.KeyPairGenerator  keygen=java.security.KeyPairGenerator.getInstance("DSA");
	
	  keygen.initialize(512);
	  KeyPair keys=keygen.genKeyPair();

	  PublicKey pubkey=keys.getPublic();
	  PrivateKey prikey=keys.getPrivate();
	  java.io.ObjectOutputStream out=new java.io.ObjectOutputStream(new java.io.FileOutputStream("myprikey.dat"));
	  out.writeObject(prikey);
	  out.close();
	  System.out.println(" prikeys ok");
	  out=new java.io.ObjectOutputStream(new java.io.FileOutputStream("mypubkey.dat"));
	   out.writeObject(pubkey);
	   out.close();
	   System.out.println(" pubkeys ok");
	   System.out.println("");
	   return true;
	  }
	  catch (java.lang.Exception e) {
	   e.printStackTrace();
	   System.out.println("");
	   return false;
	   }
	  }
	  public String byte2hex(byte[] b)
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
