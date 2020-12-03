
import javax.crypto.*;
import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SessionEncrypter {
    private byte[] KeyBytes;
    private byte[] IVBytes;
    private Cipher cipher;
    
    public SessionEncrypter (Integer keylength) throws NoSuchAlgorithmException, NoSuchPaddingException,InvalidKeyException, InvalidAlgorithmParameterException  {
        KeyGenerator Key = KeyGenerator.getInstance("AES");
        SecureRandom sec = new SecureRandom();
        Key.init(keylength,sec);
        SecretKey mykey = Key.generateKey();
        this.KeyBytes = mykey.getEncoded();
        this.cipher = Cipher.getInstance("AES/CTR/NOPadding");
        this.IVBytes = new byte [cipher.getBlockSize()];
        SecureRandom IV = new SecureRandom();
        IV.nextBytes(IVBytes);
        IvParameterSpec ivspec = new IvParameterSpec(IVBytes);
        this.IVBytes = ivspec.getIV();
        this.cipher.init(Cipher.ENCRYPT_MODE, mykey, ivspec);
    }
    
    public SessionEncrypter (byte[] keybytes, byte[] ivbytes) throws NoSuchAlgorithmException,NoSuchPaddingException,InvalidKeyException,InvalidAlgorithmParameterException{
        this.cipher = Cipher.getInstance("AES/CTR/NOPadding");
        this.KeyBytes=keybytes;
        this.IVBytes=ivbytes;
        IvParameterSpec ivspec = new IvParameterSpec(ivbytes);
        SecretKey secretKey= new SecretKeySpec(keybytes,"AES"); 
        this.cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivspec);
    }
    
    public byte[] getKeyBytes(){
        return this.KeyBytes;
    }
    
    public byte[] getIVBytes(){
        return this.IVBytes;
    }
    
    public CipherOutputStream openCipherOutputStream (OutputStream output){
        CipherOutputStream cipheroutput = new CipherOutputStream(output, this.cipher);
        return cipheroutput;
    }

 
    public static void main(String[] args) {
        // TODO code application logic here
    }
    
}
