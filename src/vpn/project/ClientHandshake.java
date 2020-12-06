/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    
    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort=12345;
    public static String ClientCertificate="client.pem";

    /* Security parameters key/iv should also go here. Fill in! */
    public static X509Certificate Servercertificate;
    public static SessionDecrypter SessionDecrypter;
    public static SessionEncrypter SessionEncrypter;
    public static String SessionHost;
    public static int SessionPort;


    /**
     * Run client handshake protocol on a handshake socket. 
     * Here, we do nothing, for now.
     */ 
    public ClientHandshake(Socket handshakeSocket) throws IOException, CertificateException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "ClientHello");
        HandMessage.putParameter("Certificate", Base64.getEncoder().encodeToString(VerifyCertificate.getCertificate(ClientCertificate).getEncoded()));
        HandMessage.send(handshakeSocket);
    }
    
    public static void VerifyServerHello(Socket socket, String CA) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if(HandMessage.getParameter("MessageType").equals("ServerHello")) {
            Logger.log("ServerHello phase running");
            String cCert = HandMessage.getParameter("Certificate");
            Servercertificate = VerifyCertificate.createCertificate(cCert);
            try{
                VerifyCertificate.getVerify(VerifyCertificate.getCertificate(CA),Servercertificate);
                Logger.log("Success Server Certificate Verification");
            }
            catch(Exception E){
                socket.close();
                Logger.log("Error: Server Certificate Verification Failed");
            }
        }else{
            socket.close();
            Logger.log("MessageType Not Found!");
        }
    }
    
    public static void Forward(Socket socket, String TargetHost, String TargetPort) throws IOException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "Forward");
        HandMessage.putParameter("TargetHost", TargetHost);
        HandMessage.putParameter("TargetPort", TargetPort);
        System.out.println("target host and port" + TargetHost + TargetPort);
        HandMessage.send(socket);
        Logger.log("Portforwarding Succeeded");
    }
    
    public static void VerifySession(Socket socket, String PrivKey) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if(HandMessage.getParameter("MessageType").equals("Session")){
            String sKey = HandMessage.getParameter("SessionKey");
            String sIV = HandMessage.getParameter("SessionIV");
            sessionHost = HandMessage.getParameter("SessionHost");
            sessionPort = Integer.parseInt(HandMessage.getParameter("SessionPort"));
            System.out.println("verify session"+sessionPort);
            byte[] SessKeyDec = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sKey),HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));
            byte[] SessIVDec = HandshakeCrypto.decrypt(Base64.getDecoder().decode(sIV),HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));

            SessionEncrypter = new SessionEncrypter(SessKeyDec, SessIVDec);
            SessionDecrypter = new SessionDecrypter(SessKeyDec,SessIVDec);
             System.out.println("chiave in byte"+ Arrays.toString(SessKeyDec));
             System.out.println("IV in byte"+ Arrays.toString(SessIVDec));
        } else{
            socket.close();
        }
    }
    
    public static String getSessionHost() { 
        return sessionHost; 
    }

    public static int getSessionPort() { 
        return sessionPort; 
    }
    
    public static SessionDecrypter getSessionDecrypter() { return SessionDecrypter; }

    public static SessionEncrypter getSessionEncrypter() { return SessionEncrypter; }
}
