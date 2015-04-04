package DESEDE;

import java.security.spec.KeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;
 
public class DESEDE {
 
    private static final String UNICODE_FORMAT = "UTF8";
    public static final String DESEDE_ENCRYPTION_SCHEME = "DESede";
    private KeySpec myKeySpec;
    private SecretKeyFactory mySecretKeyFactory;
    private Cipher cipher;
    byte[] keyAsBytes;
    private String myEncryptionKey;
    private String myEncryptionScheme;
    SecretKey key;
 
    public DESEDE() throws Exception
    {
        myEncryptionKey = "ThisIsSecretEncryptionKey";
        myEncryptionScheme = DESEDE_ENCRYPTION_SCHEME;
        keyAsBytes = myEncryptionKey.getBytes(UNICODE_FORMAT);
        myKeySpec = new DESedeKeySpec(keyAsBytes);
        mySecretKeyFactory = SecretKeyFactory.getInstance(myEncryptionScheme);
        cipher = Cipher.getInstance(myEncryptionScheme);
        key = mySecretKeyFactory.generateSecret(myKeySpec);
    }
 
    /**
     * Method To Encrypt The String
     */
    public String encrypt(String unencryptedString) {
        String encryptedString = null;
        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);
            byte[] plainText = unencryptedString.getBytes(UNICODE_FORMAT);
            byte[] encryptedText = cipher.doFinal(plainText);
            BASE64Encoder base64encoder = new BASE64Encoder();
            encryptedString = base64encoder.encode(encryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return encryptedString;
    }
    /**
     * Method To Decrypt An Ecrypted String
     */
    public String decrypt(String encryptedString) {
        String decryptedText=null;
        try {
            cipher.init(Cipher.DECRYPT_MODE, key);
            BASE64Decoder base64decoder = new BASE64Decoder();
            byte[] encryptedText = base64decoder.decodeBuffer(encryptedString);
            byte[] plainText = cipher.doFinal(encryptedText);
            decryptedText= bytes2String(plainText);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return decryptedText;
    }
    /**
     * Returns String From An Array Of Bytes
     */
    private static String bytes2String(byte[] bytes) {
        StringBuffer stringBuffer = new StringBuffer();
        for (int i = 0; i<bytes.length; i++) {
            stringBuffer.append((char) bytes[i]);
        }
        return stringBuffer.toString();
    }
 
    /**
     * Testing The DESede Encryption And Decryption Technique
     */
    public static void main(String args []) throws Exception
    {
        DESEDE myEncryptor= new DESEDE();
 
        String stringToEncrypt="We have learnt JCA (Java Cryptography Architecture) which is guided by two principles: 1. algorithm independence and extensibility. 2. implementation independence and interoperability. The aim of the JCA is to let API users use cryptographic services without concern for the implementations or even the algorithms being used to implement these services.";
        String encrypted=myEncryptor.encrypt(stringToEncrypt);
        String decrypted=myEncryptor.decrypt(encrypted);
 
        System.out.println("String To Encrypt: "+stringToEncrypt);
        System.out.println("Encrypted Value :" + encrypted);
        System.out.println("Decrypted Value :"+decrypted);
 
    }
 
}
