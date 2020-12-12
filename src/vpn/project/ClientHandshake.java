
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.naming.InvalidNameException;

public class ClientHandshake {

    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */

 /* Session host/port  */
    public static String sessionHost;
    public static int sessionPort;
    public static String ClientCertificate;
    //public static String sessionHost = "localhost";
    //public static int sessionPort=12345;
    //public static String ClientCertificate="client.pem";

    /* Security parameters key/iv should also go here. Fill in! */
    public static X509Certificate Servercertificate;
    public static SessionDecrypter SessionDecrypter;
    public static SessionEncrypter SessionEncrypter;

    /**
     * Run client handshake protocol on a handshake socket. Here, we do nothing,
     * for now.
     */
    public ClientHandshake(Socket handshakeSocket, String user) throws IOException, CertificateException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "ClientHello");
        ClientCertificate = user;
        HandMessage.putParameter("Certificate", Base64.getEncoder().encodeToString(VerifyCertificate.getCertificate(ClientCertificate).getEncoded()));
        HandMessage.send(handshakeSocket);
    }

    public static void VerifyServerHello(Socket socket, String CA) throws IOException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidNameException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if (HandMessage.getParameter("MessageType").equals("ServerHello")) {
            Logger.log("ServerHello phase running");
            String cCert = HandMessage.getParameter("Certificate");
            Servercertificate = VerifyCertificate.createCertificate(cCert);
            //check CN
            X509Certificate CA1 = VerifyCertificate.getCertificate(CA);
            if (CA1.getSubjectDN().toString().contains("CN=ca-pf.ik2206.kth.se")) {
                System.out.println("CA CN OK");
                System.out.println(CA1.getSubjectDN().toString());
            } else {
                socket.close();
                System.out.println("CA CN KO");
                System.out.println(CA1.getSubjectDN().toString());
            }
            //check mail with @kth.se
            String patternString = "EMAILADDRESS=([^@,]*@kth\\.se)";
            Pattern pattern = Pattern.compile(patternString);
            Matcher matcher = pattern.matcher(CA1.getSubjectDN().toString());
            if (matcher.find()) {
                System.out.println("CA mail OK");
            } else {
                System.out.println("CA mail KO");
                socket.close();
            }
            //check CN
            if (Servercertificate.getSubjectDN().toString().contains("CN=server-pf.ik2206.kth.se")) {
                System.out.println("SERVER CN OK");
                System.out.println(Servercertificate.getSubjectDN().toString());
            } else {
                socket.close();
                System.out.println("SERVER CN KO");
                System.out.println(Servercertificate.getSubjectDN().toString());
            }
            //check mail with @kth.se
            patternString = "EMAILADDRESS=([^@,]*@kth\\.se)";
            pattern = Pattern.compile(patternString);
            matcher = pattern.matcher(Servercertificate.getSubjectDN().toString());
            //to debug
            //matcher = pattern.matcher("EMAILADDRESS=CIAO@kth1se");
            if (matcher.find()) {
                System.out.println("SERVER mail OK");
            } else {
                System.out.println("SERVER mail KO");
                socket.close();
            }

            try {
                VerifyCertificate.getVerify(VerifyCertificate.getCertificate(CA), Servercertificate);
                Logger.log("Success Server Certificate Verification");
            } catch (Exception E) {
                socket.close();
                Logger.log("Error: Server Certificate Verification Failed");
            }
        } else {
            socket.close();
            Logger.log("MessageType Not Found!");
        }
    }

    public static void Forward(Socket socket, String TargetHost, String TargetPort) throws IOException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.putParameter("MessageType", "Forward");
        HandMessage.putParameter("TargetHost", TargetHost);
        HandMessage.putParameter("TargetPort", TargetPort);
        HandMessage.send(socket);
        Logger.log("Portforwarding Succeeded");
    }

    public static void VerifySession(Socket socket, String PrivKey) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, BadPaddingException, InvalidAlgorithmParameterException {
        HandshakeMessage HandMessage = new HandshakeMessage();
        HandMessage.recv(socket);
        if (HandMessage.getParameter("MessageType").equals("Session")) {
            String Key = HandMessage.getParameter("SessionKey");
            String IV = HandMessage.getParameter("SessionIV");
            sessionHost = HandMessage.getParameter("SessionHost");
            sessionPort = Integer.parseInt(HandMessage.getParameter("SessionPort"));
            byte[] SessKey = HandshakeCrypto.decrypt(Base64.getDecoder().decode(Key), HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));
            byte[] SessIV = HandshakeCrypto.decrypt(Base64.getDecoder().decode(IV), HandshakeCrypto.getPrivateKeyFromKeyFile(PrivKey));
            SessionEncrypter = new SessionEncrypter(SessKey, SessIV);
            SessionDecrypter = new SessionDecrypter(SessKey, SessIV);
            //System.out.println("chiave in byte"+ Arrays.toString(SessKey));
            //System.out.println("IV in byte"+ Arrays.toString(SessIV));
        } else {
            socket.close();
        }
    }

    public static String getSessionHost() {
        return sessionHost;
    }

    public static int getSessionPort() {
        return sessionPort;
    }

    public static SessionDecrypter getSessionDecrypter() {
        return SessionDecrypter;
    }

    public static SessionEncrypter getSessionEncrypter() {
        return SessionEncrypter;
    }
}
