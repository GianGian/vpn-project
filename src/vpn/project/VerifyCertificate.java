
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.util.Date;

public class VerifyCertificate { 
    public static X509Certificate getCertificate(String Certificate) throws IOException, CertificateException {
        InputStream inputStream = new FileInputStream(Certificate);
        CertificateFactory certf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate;
        certificate = (X509Certificate) certf.generateCertificate(inputStream);
        return certificate;
    }

    public static void getVerify(X509Certificate CA, X509Certificate User) throws Exception {
        try {
            Date date = new Date (System.currentTimeMillis());
            CA.verify(CA.getPublicKey());
            User.verify(CA.getPublicKey());
            CA.checkValidity(date);
            User.checkValidity(date);
            System.out.println("Pass");
        }
        catch(Exception E){
           System.out.println("Fail");
        }
    }
    
    public static X509Certificate createCertificate(String Certificate) throws CertificateException {
        CertificateFactory cert = CertificateFactory.getInstance("X.509");
        byte [] certByte = java.util.Base64.getDecoder().decode(Certificate);
        InputStream inStream = new ByteArrayInputStream(certByte);
        return (X509Certificate) cert.generateCertificate(inStream);
    }

    public static void main(String[] args) throws Exception {
        String CA = args[0];
        String User = args[1];
        System.out.println(getCertificate(CA).getSubjectDN());
        System.out.println(getCertificate(User).getSubjectDN());
        getVerify(getCertificate(CA), getCertificate(User));
    }
}