import javax.crypto.*;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SessionDecrypter {
    private Cipher cipher;

    public SessionDecrypter(byte[] keybytes, byte[] ivbytes)throws NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException{
        this.cipher = Cipher.getInstance("AES/CTR/NOPadding");
        IvParameterSpec ivspec = new IvParameterSpec(ivbytes);
        SecretKey myKey= new SecretKeySpec(keybytes,"AES"); 
        this.cipher.init(Cipher.DECRYPT_MODE, myKey, ivspec);
    }
    
    public CipherInputStream openCipherInputStream(InputStream input){
        CipherInputStream cipherinput = new CipherInputStream(input, this.cipher);
        return cipherinput;
    }
    
    public static void main(String[] args) {
        // TODO code application logic here
    }
    
}  
    
