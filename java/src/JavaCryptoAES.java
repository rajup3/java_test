import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES encryption in Java and Android
 * @author raju patel
 *
 */
public class JavaCryptoAES {
   
	/**
	 * Encrypt
	 * 
	 * @param cipher_key
	 * @param plain_text_to_encrypt
	 * @return
	 */
	public static String encrypt(String cipher_key, String plain_text_to_encrypt){
		String base64_cipher = null;
		try {
			ByteArrayOutputStream output = new ByteArrayOutputStream();
	    	byte[] iv_bytes = "0123456789012345".getBytes();
	    	byte[] key_bytes = md5(cipher_key);
			
	    	SecretKeySpec key = new SecretKeySpec(key_bytes, "AES");
	        IvParameterSpec ivSpec = new IvParameterSpec(iv_bytes);
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
    	
	        cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
	    	ByteArrayInputStream b_in = new ByteArrayInputStream(plain_text_to_encrypt.getBytes());
	        CipherInputStream c_in = new CipherInputStream(b_in, cipher);
	        
	        int ch;
	        while ((ch = c_in.read()) >= 0) {
	        	output.write(ch);
	        }
	        base64_cipher = new String(Base64Encoder.encode(output.toByteArray()));
	        
		} catch (Exception e) {
			e.printStackTrace();
		}
		return base64_cipher; 
	}
	
	/**
	 * Decrypt
	 * 
	 * @param cipher_key
	 * @param base64_cipher
	 * @return
	 */
	public static String decrypt(String cipher_key, String base64_cipher){
		String plain_text = null;
		try {
			byte[] cipher_text_bytes = Base64Encoder.decode(base64_cipher);
			
			ByteArrayOutputStream output = new ByteArrayOutputStream();
	    	byte[] iv_bytes = "0123456789012345".getBytes();
	    	byte[] key_bytes = md5(cipher_key);
			
	    	SecretKeySpec key = new SecretKeySpec(key_bytes, "AES");
	        IvParameterSpec ivSpec = new IvParameterSpec(iv_bytes);
	        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
	        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);
        	CipherOutputStream c_out = new CipherOutputStream(output, cipher);
        	c_out.write(cipher_text_bytes);
        	c_out.close();
        	
        	plain_text = new String(output.toByteArray()).trim();
        	
		} catch (Exception e) {
			e.printStackTrace();
		}
	    return plain_text;
	}
    
	/**
     * HMacSHA256
     * 
     * @param String secret_key
     * @param String input
     * @return String as HashText
     */
	public static String getHMacSHA256(String secret_key, String input) {
		String hashtext = null;
		try {
			Key KEY = new SecretKeySpec(input.getBytes("UTF-8"), "HmacSHA256");
			Mac sha256_HMAC = Mac.getInstance("HMACSHA256");
	    	
			sha256_HMAC.init(KEY);
			byte[] mac_data = sha256_HMAC.doFinal(secret_key.getBytes());
	    	
	    	BigInteger number = new BigInteger(1, mac_data);
	    	hashtext = number.toString(16);
            
		} catch (Exception e) {
           e.printStackTrace();
        }
		return hashtext;
	}
	
    public static void main(String[] args) throws Exception {
        String message_to_encrypt = "Hello World Hello World Hello World", cipher_key = "demo", secret_key = "demo";
        
        System.out.println(" Message to encrypt : "+message_to_encrypt);
        String base64_cipher = encrypt(cipher_key, message_to_encrypt);
        System.out.println(" Base64 encoded cipher : "+base64_cipher);
        
        String decrypted_message = decrypt(cipher_key, base64_cipher);
        System.out.println(" Decrypted message : "+decrypted_message);
        
        String hash_text = getHMacSHA256(secret_key, "Hello");
        System.out.println(" Hash text from HMacSHA256 : "+hash_text);
    }
    
    // Supported functions starts here
	public static byte[] md5(String string) { 
	    byte[] hash; 
	 
	    try { 
	        hash = MessageDigest.getInstance("MD5").digest(string.getBytes("UTF-8")); 
	    } catch (NoSuchAlgorithmException e) { 
	        throw new RuntimeException("MD5 should be supported!", e); 
	    } catch (UnsupportedEncodingException e) { 
	        throw new RuntimeException("UTF-8 should be supported!", e); 
	    } 
	 
	    StringBuilder hex = new StringBuilder(hash.length * 2); 
	    for (byte b : hash) { 
	        if ((b & 0xFF) < 0x10) hex.append("0"); 
	        hex.append(Integer.toHexString(b & 0xFF)); 
	    }
	    return hexStringToByteArray(hex.toString());
	}
	
	public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }
	// Supported functions ends here
}
