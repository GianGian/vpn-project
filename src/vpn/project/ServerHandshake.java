/**
 * Server side of the handshake.
 */

import java.net.InetAddress;
import java.net.Socket;
import java.net.ServerSocket;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
    
    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;    

    /* The final destination -- simulate handshake with constants */
    //public static String targetHost = "localhost";
    //public static int targetPort = 6789;
    //public static String ServerCertificate="server.pem";
    public static String targetHost;
    public static int targetPort;
    public static String ServerCertificate;
    /* Security parameters key/iv should also go here. Fill in! */
     public static X509Certificate Clientcertificate;
     public static SessionDecrypter SessionDecrypter;
     public static SessionEncrypter SessionEncrypter;

    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     */ 
    public ServerHandshake(Socket handshakeSocket, String user) throws IOException, CertificateException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "ServerHello");
        String ServerCertificate = user;
        HandMessage.putParameter("Certificate", Base64.getEncoder().encodeToString(VerifyCertificate.getCertificate(ServerCertificate).getEncoded()));
        HandMessage.send(handshakeSocket);
    }
    
    public static void VerifyClientHello(Socket socket, String CA) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
            if(HandMessage.getParameter("MessageType").equals("ClientHello")) {
                String UserCert = HandMessage.getParameter("Certificate");
                Clientcertificate = VerifyCertificate.createCertificate(UserCert);
                
                X509Certificate CA1= VerifyCertificate.getCertificate(CA);
            if(CA1.getSubjectDN().toString().contains("CN=ca-pf.ik2206.kth.se") && CA1.getSubjectDN().toString().contains("EMAILADDRESS=giamos@kth.se")){
                System.out.println("CA CN and mail OK");
                System.out.println(CA1.getSubjectDN().toString());
            }else{
                socket.close();
                System.out.println("CA CN and/or mail KO");
                System.out.println(CA1.getSubjectDN().toString());
            }
            
            if(Clientcertificate.getSubjectDN().toString().contains("CN=client-pf.ik2206.kth.se") && Clientcertificate.getSubjectDN().toString().contains("EMAILADDRESS=giamos@kth.se")){
                System.out.println("SERVER CN and mail OK");
                System.out.println(Clientcertificate.getSubjectDN().toString());
            }else{
                socket.close();
                System.out.println("SERVER CN and/or mail KO");
                System.out.println(Clientcertificate.getSubjectDN().toString());
            }
            
            
                try{
                    VerifyCertificate.getVerify(VerifyCertificate.getCertificate(CA),Clientcertificate);
                    Logger.log("Success Client Certificate Verification");
                }
                catch(Exception E){
                    socket.close();
                    Logger.log("Error: Client Certificate Verification Failed");
                }
            }else{
                socket.close();
                Logger.log("MessageType Not Found!");
            }
    }
    
    public static void VerifyForward(Socket socket) throws IOException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if(HandMessage.getParameter("MessageType").equals("Forward")) {
            targetHost = HandMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(HandMessage.getParameter("TargetPort"));
            Logger.log("Success. TargetHost: " + targetHost + " and TargetPort: " + targetPort);
        }else {
            socket.close();
        }
    }
    
    public static void Session(Socket socket, String serverHost, String serverPort) throws IOException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "Session");
        SessionKey key = new SessionKey(128);
        IvParameterSpec IV = new IvParameterSpec(new SecureRandom().generateSeed(16));
        PublicKey PublicUser = Clientcertificate.getPublicKey();
        HandMessage.putParameter("SessionKey", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(key.getKeyBytes(), PublicUser)));
        HandMessage.putParameter("SessionIV", Base64.getEncoder().encodeToString(HandshakeCrypto.encrypt(IV.getIV(), PublicUser)));
        SessionEncrypter = new SessionEncrypter(key.getKeyBytes(), IV.getIV());
        SessionDecrypter = new SessionDecrypter(key.getKeyBytes(), IV.getIV());
        //System.out.println("chiave in byte" + Arrays.toString(Skey.getKeyBytes()));
        //System.out.println("iv in byte" + Arrays.toString(sIV.getIV()));
        sessionHost=serverHost;
        sessionPort=Integer.parseInt(serverPort);
        HandMessage.putParameter("SessionHost", serverHost);
        HandMessage.putParameter("SessionPort", serverPort);
        HandMessage.send(socket);
    }
    
    public static String getTargetHost() { return targetHost; }

    public static int getTargetPort() { return targetPort; }
    
    public static SessionDecrypter getSessionDecrypter() { return SessionDecrypter; }

    public static SessionEncrypter getSessionEncrypter() { return SessionEncrypter; }
}
