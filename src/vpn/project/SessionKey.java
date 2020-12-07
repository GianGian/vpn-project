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
}
