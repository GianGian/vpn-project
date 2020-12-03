import javax.crypto.KeyGenerator;
import java.security.SecureRandom;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
//import java.util.Arrays;
    
public class SessionKey{       
    private SecretKey secretKey;

    public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
        KeyGenerator Key = KeyGenerator.getInstance("AES");
        SecureRandom sec = new SecureRandom();
        Key.init(keylength,sec);
        this.secretKey = Key.generateKey();
    }
    
    public SessionKey(byte[] keybytes){
        this.secretKey= new SecretKeySpec(keybytes,"AES"); 
    }
    
    public SecretKey getSecretKey(){
        return this.secretKey;
    }
    
    byte[] getKeyBytes(){
        return this.secretKey.getEncoded();
    }


/*public static void main(String[] args) throws NoSuchAlgorithmException {
        // TODO code application logic here
        SessionKey key1 = new SessionKey(128);
        //System.out.print((Arrays.toString(key1.getKeyBytes())));
        
        SessionKey key3 = new SessionKey(128);
            byte[] stream3 = key3.getKeyBytes();
            for(int i = 0; i < stream3.length; i ++)
            {
                System.out.print(Integer.toString(stream3[i],2));
                System.out.print(" ");
            }
    } */
}
