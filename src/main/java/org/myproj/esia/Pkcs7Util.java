package org.myproj.esia;


import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;
import org.bouncycastle.util.Store;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;


/**
 * Magic
 */
@Component
public final class Pkcs7Util {


    private static final String PATH_TO_KEYSTORE = "PATH_TO_KEYSTORE";
    private static final String KEY_ALIAS = "KEY_ALIAS";
    private static final String KEYSTORE_PASSWORD = "KEYSTORE_PASSWORD";
    private static final String SIGNATURE_ALG = "SIGNATURE_ALG";

    private KeyStore loadKeyStore() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException {

        KeyStore keystore = KeyStore.getInstance("JKS");
        InputStream is = new FileInputStream(PATH_TO_KEYSTORE);
        keystore.load(is, KEYSTORE_PASSWORD.toCharArray());
        return keystore;
    }

    private CMSSignedDataGenerator setUpProvider(final KeyStore keystore) throws Exception {

        Security.addProvider(new BouncyCastleProvider());
        Certificate[] certificateChain = keystore.getCertificateChain(KEY_ALIAS);
        final List<Certificate> certificates = new ArrayList<>();

        for (int i = 0, length = certificateChain == null ? 0 : certificateChain.length; i < length; i++) {
            certificates.add(certificateChain[i]);
        }

        Store store = new JcaCertStore(certificates);
        Certificate cert = keystore.getCertificate(KEY_ALIAS);
        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALG).setProvider("BC").
                build((PrivateKey) (keystore.getKey(KEY_ALIAS, KEYSTORE_PASSWORD.toCharArray())));

        CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
        generator.addSignerInfoGenerator(new JcaSignerInfoGeneratorBuilder(new JcaDigestCalculatorProviderBuilder().setProvider("BC").
                build()).build(signer, (X509Certificate) cert));

        generator.addCertificates(store);

        return generator;
    }

    private byte[] signPkcs7(final byte[] content, final CMSSignedDataGenerator generator) throws CMSException, IOException {
        CMSTypedData cmsTypedData = new CMSProcessableByteArray(content);
        CMSSignedData signedData = generator.generate(cmsTypedData, true);
        return signedData.getEncoded();
    }

    public String getUrlSafeSign(final String content) {
        try {
            byte[] signedBytes = signPkcs7(content.getBytes("UTF-8"), setUpProvider(loadKeyStore()));
            return new String(Base64.getUrlEncoder().encode(signedBytes));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
