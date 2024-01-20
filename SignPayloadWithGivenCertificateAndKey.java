import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

public class SignPayloadWithGivenCertificateAndKey {

    public static void main(String[] args) throws Exception {
        // Security.addProvider(new BouncyCastleProvider());
        
        // if (args.length < 1) {
        //     System.out.println("Please provide your payload to be signed as command line argument");
        //     return;
        // }
        // final String payloadToBeSigned = args[0];
        final String privateKeyStringWithoutHeadersOrNewLines = "MIIE...";
        final String certificateStringWithoutHeadersOrNewLines = "MIIH...";

        byte[] data = payloadToBeSigned
                .replaceAll("\\n[ ]*", "")
                .replaceAll("\\r[ ]*", "")
                .replaceAll(":[ ]*", ":")
                .getBytes("UTF-8");


        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpecPKCS8 = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyStringWithoutHeadersOrNewLines));

        PrivateKey privateKey = kf.generatePrivate(keySpecPKCS8);

        CertificateFactory factory = CertificateFactory.getInstance("X509");
        byte[] certificateDecoded = Base64.getDecoder().decode(certificateStringWithoutHeadersOrNewLines);
        Certificate cert = factory.generateCertificate(new ByteArrayInputStream(certificateDecoded));
        String algorythm = ((X509Certificate)cert).getSigAlgName();

        Signature sig = Signature.getInstance(algorythm);
        sig.initSign(privateKey);
        sig.update(data);
        byte[] signatureBytes = sig.sign();
        System.out.println("Private: " + privateKeyStringWithoutHeadersOrNewLines);
        System.out.println("Public: " + certificateStringWithoutHeadersOrNewLines);
        System.out.println("Algorithm: " + algorythm);
        System.out.println("Challenge: " + payloadToBeSigned);
        System.out.println("Signature: " + new String(Base64.getEncoder().encode(signatureBytes)));
    }
}