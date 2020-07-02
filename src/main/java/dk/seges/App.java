package dk.seges;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SamlAssertionWrapper;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class App {
    public static void main(String[] args) {
        final String audience = "https://www.landmand.dk/";
        final String trustedSigningCertBase64File = ".\\data\\idp_dlbr_dk_signing_public.cer";
        final String saml2TokenFile = ".\\data\\token.xml";

        try {
            String current = new java.io.File( "." ).getCanonicalPath();
            System.out.println("Current dir:"+current);
            List<String> audienceRestrictions = new ArrayList<String>();
            audienceRestrictions.add(audience);
            X509Certificate trustedSigningCert = loadCertificateFromBase64File(trustedSigningCertBase64File);
            PublicKey trustedSigningCertPublic = trustedSigningCert.getPublicKey();

            SamlAssertionWrapper wrapper = LoadSamlAssertionWrapperFromFile(saml2TokenFile);
            X509Certificate tokenCert = LoadCertificateFromToken(wrapper);
            PublicKey tokenCertPublic = tokenCert.getPublicKey();

            // Technically not necessary since we are verifying the signature with the trusted public key,
            // not the one inside the SAML token
            boolean tokenSignedWithTrustedSigningCert = tokenCertPublic == trustedSigningCertPublic;
            System.out.printf("Token is signed with trusted signing cert? %s%n", tokenSignedWithTrustedSigningCert);

            // Can be tested by changing SAML token contents
            System.out.println("Verifying signature on token (will throw if invalid)");
            SAMLKeyInfo trustedKey = new SAMLKeyInfo();
            trustedKey.setPublicKey(trustedSigningCertPublic);
            wrapper.verifySignature(trustedKey);
            // Can be tested by changing accepted audiences (in audienceRestrictions) above
            System.out.println("Verifying audience on token (will throw if invalid)");
            wrapper.checkAudienceRestrictions(audienceRestrictions);
            // Can be tested by waiting until the token expires (default: 1 hour)
            System.out.println("Verifying token not expired (will throw if invalid)");
            wrapper.checkConditions(0);
            // Additional checks exists but are not essential

            // Dump the data
            String subjectName = wrapper.getSubjectName();
            System.out.printf("Subject name: %s%n", subjectName);

            List<AttributeStatement> claims = wrapper.getSaml2().getAttributeStatements();
            for (AttributeStatement claim : claims) {
                for (Attribute attribute : claim.getAttributes()) {
                    System.out.println(attribute.getName() + " -> ");
                    for (XMLObject value : attribute.getAttributeValues()) {
                        System.out.println("   " + value.getDOM().getTextContent());
                    }
                }

            }
            System.out.println("Done");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static ByteArrayInputStream readFile(final String filePath) throws IOException {
        return new ByteArrayInputStream(Files.readAllBytes(new File(filePath).toPath()));
    }

    private static java.security.cert.X509Certificate createCertificateFromBase64Bytes(byte[] b64) throws CertificateException {
        final byte[] certBytes = Base64.getDecoder().decode(b64);
        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        ByteArrayInputStream stream = new ByteArrayInputStream(certBytes);
        java.security.cert.X509Certificate cert =
                (java.security.cert.X509Certificate) certFactory.generateCertificate(stream);
        return cert;
    }

    private static java.security.cert.X509Certificate loadCertificateFromBase64File(String file) throws CertificateException, IOException {
        byte[] certB64Bytes = Files.readAllBytes(new File(file).toPath());
        return createCertificateFromBase64Bytes(certB64Bytes);
    }


    private static X509Certificate LoadCertificateFromToken(SamlAssertionWrapper wrapper) throws UnsupportedEncodingException, CertificateException {
        Assertion assertion = wrapper.getSaml2();
        Signature signature = assertion.getSignature();
        List<X509Data> x509Datas = signature.getKeyInfo().getX509Datas();
        org.opensaml.xmlsec.signature.X509Certificate tokenSignatureCertificate = x509Datas.get(0).getX509Certificates().get(0);
        String base64CertPublicKey = tokenSignatureCertificate.getValue();
        byte[] certPublicKeyBytes = base64CertPublicKey.getBytes("UTF-8");
        return createCertificateFromBase64Bytes(certPublicKeyBytes);
    }

    private static SamlAssertionWrapper LoadSamlAssertionWrapperFromFile(String file) throws IOException, ParserConfigurationException, SAXException, WSSecurityException {
        final ByteArrayInputStream is = readFile(file);
        final DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
        dbFactory.setNamespaceAware(true);
        final DocumentBuilder builder = dbFactory.newDocumentBuilder();
        final Document doc = builder.parse(is);

        final NodeList assertionList = doc.getElementsByTagName("Assertion");
        final Node assertionNode = assertionList.item(0);
        final Element assertionElement = (Element) assertionNode;
        return new SamlAssertionWrapper(assertionElement);
    }
}