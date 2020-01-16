import java.util.*;
import security.Security;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Login {

    private static SecretKey secretKey;
    private static String configPW;
    private static String configSalt;

    public static void main(String[] args){

        configPW = "my Super secret password";
        configSalt = "salty1234";

        //secretKey = Security.generateSecretKey();
        //secretKey = Security.generateSecretKeyFromPassword(configPW, configSalt);
        secretKey = Security.generateSecretKeyFromPasswordRandomSalt(configPW);

        Map<String,String> users = new HashMap<String, String>();
        users.put("daniel",Security.hash("password"));

        Scanner in = new Scanner(System.in);

        System.out.print("Username:");
        String user = in.nextLine();
        System.out.print("Password:");
        String password = in.nextLine();

        String hashedPasswordInput = Security.hash(password);

        if(users.containsKey(user) && users.get(user).equals(hashedPasswordInput)){
            System.out.println("Signed In");
        } else {
            System.out.println("User or Password is incorrect");
        }

        in.close();

        String originalString = password;
        String HashedString = Security.hash(originalString);
        String encryptedString = Security.encrypt(originalString, secretKey);
        String decryptedString = Security.decrypt(encryptedString, secretKey);

        System.out.println("Original String:" + originalString);
        System.out.println("Hashed String:" + HashedString);
        System.out.println("Encrypted String:" + encryptedString);
        System.out.println("Decrypted String:" + decryptedString);

        System.out.println("Secret Key:" + Security.getSecretKeyAsString(secretKey));
    }
}