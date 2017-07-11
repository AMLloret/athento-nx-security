package org.athento.nuxeo.security.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.athento.nuxeo.security.api.TokenException;
import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.nuxeo.runtime.api.Framework;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;

/**
 * Sign helper.
 */
public final class SignHelper {

    /** Log. */
    private static final Log LOG = LogFactory.getLog(SignHelper.class);

    /**
     * Get a signed token.
     *
     * @param token
     * @return
     * @throws TokenException
     */
    public static String getSignedToken(String token) throws TokenException {
        try {
            byte[] data = token.getBytes("UTF8");
            Signature sig = Signature.getInstance("SHA1WithRSA");
            KeyPair keyPair = getKeyPair();
            sig.initSign(keyPair.getPrivate());
            sig.update(data);
            return Base64.encodeBase64String(sig.sign());
        } catch (Exception e) {
            throw new TokenException("Unable to sign the token", e);
        }
    }

    /**
     * Verify a signed token.
     *
     * @param token
     * @param sign
     * @return
     */
    public static boolean verifySignedToken(String token, String sign) {
        try {
            Signature sig = Signature.getInstance("SHA1WithRSA");
            sig.initVerify(getKeyPair().getPublic());
            sig.update(token.getBytes());
            return sig.verify(Base64.decodeBase64(sign));
        } catch (Exception e) {
            LOG.error("Unable to verify signed token ", e);
        }
        return false;
    }

    /**
     * Get a key pair.
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws InvalidKeySpecException
     * @throws TokenException
     */
    private static KeyPair getKeyPair() throws NoSuchAlgorithmException, InvalidKeyException, IOException, InvalidKeySpecException, TokenException {
        String privateKeyFilename;
        if (Framework.isInitialized()) {
            privateKeyFilename = Framework.getProperty("athento.key.filename");
            if (privateKeyFilename == null) {
                throw new TokenException("Please check athento.privatekey.filename property");
            }
        } else {
            privateKeyFilename = Thread.currentThread().getContextClassLoader().getResource("sign/examplePrivateKey.txt").getFile();
        }
        PrivateKey privateKey = readPrivateKey(privateKeyFilename);
        RSAPrivateCrtKey privk = (RSAPrivateCrtKey) privateKey;
        RSAPublicKeySpec publicKeySpec = new java.security.spec.RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent());
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Read a private key from filename.
     *
     * @param filename
     * @return
     * @throws java.io.IOException
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     */
    private static PrivateKey readPrivateKey(String filename) throws
            java.io.IOException,
            java.security.NoSuchAlgorithmException,
            java.security.spec.InvalidKeySpecException {
        String pemString = FileUtils.readFileToString(new File(filename));
        pemString = pemString.replace("-----BEGIN RSA PRIVATE KEY-----\n", "");
        pemString = pemString.replace("-----END RSA PRIVATE KEY-----", "");
        pemString = pemString.replaceAll("\\s+","");
        byte[] data = Base64.decodeBase64(pemString);
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1Integer(0));
        ASN1EncodableVector v2 = new ASN1EncodableVector();
        v2.add(new ASN1ObjectIdentifier(PKCSObjectIdentifiers.rsaEncryption.getId()));
        v2.add(DERNull.INSTANCE);
        v.add(new DERSequence(v2));
        v.add(new DEROctetString(data));
        ASN1Sequence seq = new DERSequence(v);
        byte[] privKey = seq.getEncoded("DER");
        PKCS8EncodedKeySpec spec = new  PKCS8EncodedKeySpec(privKey);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        return fact.generatePrivate(spec);
    }

}
