/* GC Security Package */
package security;

import java.util.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEParameterSpec;

import java.util.Base64;

public class Security {

    public static String hash(String plainText){
        try{
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(plainText.getBytes());
            byte[] digest = md.digest();
            StringBuffer sb = new StringBuffer();
            for (byte b : digest) {
                sb.append(String.format("%02x", b & 0xff));
            }
            
            String hash = sb.toString();
            
            return hash;
        }
        catch (NoSuchAlgorithmException e){
            System.err.println("MD5 is not a valid message digest algorithm");
        }
        catch(Exception ex){
            ex.printStackTrace();
        }

        return null;
    }

    public static String encrypt(String plainText, SecretKey secretKey){
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE,secretKey);

            byte[] data = plainText.getBytes("UTF-8");

            return Base64.getEncoder().encodeToString(cipher.doFinal(data));

        } catch (NoSuchAlgorithmException e){
            e.printStackTrace();
        }catch(Exception ex){
            ex.printStackTrace();
        }

        return null;
    
    }

    public static String decrypt(String cipherText, SecretKey secretKey){
        try{
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE,secretKey);

            return new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
        }catch(Exception e){
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static SecretKey generateSecretKey(){
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        }
        catch (Exception e){
            e.printStackTrace();
        }

        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    public static SecretKey generateSecretKeyFromPassword(String password, String salt){
        try{
            byte[] saltBytes = salt.getBytes();
            PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray(), saltBytes, 1000, 128);
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKey key = (PBEKey) factory.generateSecret(keySpec);
            SecretKey encKey = new SecretKeySpec(key.getEncoded(), "AES");
            return encKey;
        } catch (Exception e){
            e.printStackTrace();
        }
        return null;
    }

    public static SecretKey generateSecretKeyFromPasswordRandomSalt(String password){
        byte[] saltBytes = null;
        try{
            SecureRandom rand = SecureRandom.getInstance("SHA1PRNG");
            saltBytes = new byte[16];
            rand.nextBytes(saltBytes);
        } catch(Exception e){
            e.printStackTrace();
        }

        return generateSecretKeyFromPassword(password, new String(saltBytes));
    }

    public static String getSecretKeyAsString(SecretKey secretKey){
        byte[] encoded = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(encoded);
    }
}