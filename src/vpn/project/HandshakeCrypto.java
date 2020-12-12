
import javax.crypto.*;
import java.security.NoSuchAlgorithmException;
import java.security.InvalidKeyException;
import java.security.InvalidAlgorithmParameterException;
import javax.crypto.Cipher;
import java.security.*;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

public class HandshakeCrypto {

    public static byte[] encrypt(byte[] plaintext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] cipherText = cipher.doFinal(plaintext);
        return cipherText;
    }

    public static byte[] decrypt(byte[] ciphertext, Key key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] plainText = cipher.doFinal(ciphertext);
        return plainText;
    }

    public static PublicKey getPublicKeyFromCertFile(String certfile) throws IOException, CertificateException {
        InputStream inputStream = new FileInputStream(certfile);
        CertificateFactory cert = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;
        certificate = (X509Certificate) cert.generateCertificate(inputStream);
        return certificate.getPublicKey();
    }

    public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        //from https://stackoverflow.com/questions/20119874/how-to-load-the-private-key-from-a-der-file-into-java-private-key-object
        Path path = Paths.get(keyfile);
        byte[] privKeyByteArray = Files.readAllBytes(path);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
        KeyFactory key = KeyFactory.getInstance("RSA");
        PrivateKey privatekey = key.generatePrivate(keySpec);
        return privatekey;
    }
}
