/*
 * Copyright (c) 2025, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Oracle designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package java.security;

import jdk.internal.javac.PreviewFeature;

import sun.security.pkcs.PKCS8Key;
import sun.security.rsa.RSAPrivateCrtKeyImpl;
import sun.security.util.Pem;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.PBEKeySpec;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.cert.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Objects;

/**
 * {@code PEMDecoder} implements a decoder for Privacy-Enhanced Mail (PEM) data.
 * PEM is a textual encoding used to store and transfer security
 * objects, such as asymmetric keys, certificates, and certificate revocation
 * lists (CRLs).  It is defined in RFC 1421 and RFC 7468.  PEM consists of a
 * Base64-formatted binary encoding enclosed by a type-identifying header
 * and footer.
 *
 * <p> The {@linkplain #decode(String)} and {@linkplain #decode(InputStream)}
 * methods return an instance of a class that matches the data
 * type and implements {@link DEREncodable}. The
 * following types are decoded into Java Cryptographic Extensions (JCE) object
 * representations:
 * <pre>
 *     PRIVATE KEY, RSA PRIVATE KEY, PUBLIC KEY, CERTIFICATE,
 *     X509 CERTIFICATE, X509 CRL, and ENCRYPTED PRIVATE KEY.
 * </pre>
 *
 * <p> If the PEM does not have a JCE object representation, it returns a
 * {@link PEMRecord}. Any PEM can be decoded into a {@code PEMRecord} if the
 * class is specified.
 *
 * <p> The {@linkplain #decode(String, Class)} and
 * {@linkplain #decode(InputStream, Class)} methods take a Class parameter
 * which determines the type of {@code DEREncodable} that is returned. These
 * methods are useful when casting, extracting, or changing return class.
 * {@code ECPublicKey.class} can be used to cast a {@code PublicKey}
 * to a {@code ECPublicKey}. The Class parameter can specify the returned
 * key object from a PEM containing a public and private key.  If only
 * the private key is required, {@code PrivateKey.class} can be used.
 * If the Class parameter is set to {@code X509EncodedKeySpec.class}, the
 * public key will be returned in that format.  Any type of PEM data can be
 * decoded into a {@code PEMRecord} by specifying {@code PEMRecord.class}.
 * If the Class parameter doesn't match the PEM content, an
 * {@code IllegalArgumentException} will be thrown.
 *
 * <p> A new {@code PEMDecoder} instance is created when configured
 * with {@linkplain #withFactory(Provider)} and/or
 * {@linkplain #withDecryption(char[])}. {@linkplain #withFactory(Provider)}
 * configures the decoder to use only {@linkplain KeyFactory} and
 * {@linkplain CertificateFactory} instances from the given {@code Provider}.
 * {@link#withDecryption(char[])} configures the decoder to decrypt all
 * encrypted private key PEM data using the given password.
 * Configuring an instance for decryption does not prevent decoding with
 * unencrypted PEM. Any encrypted PEM that does not use the configured password
 * will throw a {@link RuntimeException}. When encrypted PEM is used with a
 * decoder not configured for decryption, an {@link EncryptedPrivateKeyInfo}
 * object is returned.  {@code EncryptedPrivateKeyInfo} methods must be used to
 * retrieve the {@link PrivateKey}.
 *
 * <p> Byte streams consumed by methods in this class are assumed to represent
 * characters encoded in the
 * {@link java.nio.charset.StandardCharsets#ISO_8859_1 ISO-8859-1} charset.
 *
 * <p>This class is immutable and thread-safe.
 *
 * <p> Here is an example of decoding a {@code PrivateKey} object:
 * {@snippet lang = java:
 *     PEMDecoder pd = PEMDecoder.of();
 *     PrivateKey priKey = pd.decode(priKeyPEM, PrivateKey.class);
 * }
 *
 * @see PEMEncoder
 * @see PEMRecord
 * @see EncryptedPrivateKeyInfo
 *
 * @spec https://www.rfc-editor.org/info/rfc1421
 *       RFC 1421: Privacy Enhancement for Internet Electronic Mail
 * @spec https://www.rfc-editor.org/info/rfc7468
 *       RFC 7468: Textual Encodings of PKIX, PKCS, and CMS Structures
 *
 * @since 25
 */

@PreviewFeature(feature = PreviewFeature.Feature.PEM_API)
public final class PEMDecoder {
    private final Provider factory;
    private final PBEKeySpec password;

    // Singleton instance for PEMDecoder
    private final static PEMDecoder PEM_DECODER = new PEMDecoder(null, null);

    /**
     * Creates an instance with a specific KeyFactory and/or password.
     * @param withFactory KeyFactory provider
     * @param withPassword char[] password for EncryptedPrivateKeyInfo
     *                    decryption
     */
    private PEMDecoder(Provider withFactory, PBEKeySpec withPassword) {
        password = withPassword;
        factory = withFactory;
    }

    /**
     * Returns an instance of {@code PEMDecoder}.
     *
     * @return new {@code PEMDecoder} instance
     */
    public static PEMDecoder of() {
        return PEM_DECODER;
    }

    /**
     * After the header, footer, and base64 have been separated, identify the
     * header and footer and proceed with decoding the base64 for the
     * appropriate type.
     */
    private DEREncodable decode(PEMRecord pem) {
        Base64.Decoder decoder = Base64.getMimeDecoder();
        if (pem.type() == null) {
            return pem;
        }

        try {
            return switch (pem.type()) {
                case Pem.PUBLIC_KEY -> {
                    X509EncodedKeySpec spec =
                        new X509EncodedKeySpec(decoder.decode(pem.pem()));
                    yield (getKeyFactory(spec.getAlgorithm())).
                        generatePublic(spec);
                }
                case Pem.PRIVATE_KEY -> {
                    PKCS8Key p8key = new PKCS8Key(decoder.decode(pem.pem()));
                    String algo = p8key.getAlgorithm();
                    KeyFactory kf = getKeyFactory(algo);
                    DEREncodable d = kf.generatePrivate(
                        new PKCS8EncodedKeySpec(p8key.getEncoded(), algo));

                    // Look for a public key inside the pkcs8 encoding.
                    if (p8key.getPubKeyEncoded() != null) {
                        // Check if this is a OneAsymmetricKey encoding
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(
                            p8key.getPubKeyEncoded(), algo);
                        yield new KeyPair(getKeyFactory(algo).
                            generatePublic(spec), (PrivateKey) d);

                    } else if (d instanceof PKCS8Key p8 &&
                        p8.getPubKeyEncoded() != null) {
                        // If the KeyFactory decoded an algorithm-specific
                        // encodings, look for the public key again.  This
                        // happens with EC and SEC1-v2 encoding
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(
                            p8.getPubKeyEncoded(), algo);
                        yield new KeyPair(getKeyFactory(algo).
                            generatePublic(spec), p8);
                    } else {
                        // No public key, return the private key.
                        yield d;
                    }
                }
                case Pem.ENCRYPTED_PRIVATE_KEY -> {
                    if (password == null) {
                        yield new EncryptedPrivateKeyInfo(decoder.decode(
                            pem.pem()));
                    }
                    yield new EncryptedPrivateKeyInfo(decoder.decode(pem.pem())).
                        getKey(password.getPassword());
                }
                case Pem.CERTIFICATE, Pem.X509_CERTIFICATE,
                     Pem.X_509_CERTIFICATE -> {
                    CertificateFactory cf = getCertFactory("X509");
                    yield (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(decoder.decode(pem.pem())));
                }
                case Pem.X509_CRL, Pem.CRL -> {
                    CertificateFactory cf = getCertFactory("X509");
                    yield (X509CRL) cf.generateCRL(
                        new ByteArrayInputStream(decoder.decode(pem.pem())));
                }
                case Pem.RSA_PRIVATE_KEY -> {
                    KeyFactory kf = getKeyFactory("RSA");
                    yield kf.generatePrivate(
                        RSAPrivateCrtKeyImpl.getKeySpec(decoder.decode(
                            pem.pem())));
                }
                default -> pem;
            };
        } catch (GeneralSecurityException | IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Decodes and returns a {@link DEREncodable} from the given {@code String}.
     *
     * <p>This method reads the {@code String} until PEM data is found or until
     * the end is reached.  Non-PEM data before the PEM header is ignored by
     * the decoder.
     *
     * @param str a String containing PEM data
     * @return {@code DEREncodable} generated from the PEM data.
     * @throws IllegalArgumentException on error in decoding.
     * @throws NullPointerException when {@code str} is null.
     */
    public DEREncodable decode(String str) {
        Objects.requireNonNull(str);
        try {
            return decode(new ByteArrayInputStream(
                str.getBytes(StandardCharsets.ISO_8859_1)));
        } catch (IOException e) {
            // With all data contained in the String, there are no IO ops.
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Decodes and returns a {@link DEREncodable} from the given
     * {@code InputStream}.
     *
     * <p>This method reads the {@code InputStream} until PEM data is
     * found or until the end of the stream.  Non-PEM data in the
     * {@code InputStream} before the PEM header is ignored by the decoder.
     *
     * @param is InputStream containing PEM data
     * @return {@code DEREncodable} generated from the data read.
     * @throws IOException on IO error with the InputStream
     * @throws IllegalArgumentException on error in decoding.
     * @throws NullPointerException when {@code is} is null.
     */
    public DEREncodable decode(InputStream is) throws IOException {
        Objects.requireNonNull(is);
        PEMRecord pem = Pem.readPEM(is);
        DEREncodable d = decode(pem);
        // If d is a PEMRecord, return no leadingData and if there is no type()
        // throw IAE.
        if (d instanceof PEMRecord p) {
            if (p.type() != null) {
                if (p.leadingData() != null) {
                    return new PEMRecord(p.type(), p.pem());
                }
            } else {
                throw new IllegalArgumentException("No PEM data found.");
            }
        }
        return d;
    }

    /**
     * Decodes and returns the specified class for the given PEM string.
     * {@code tClass} must extend {@link DEREncodable} and be an appropriate
     * class for the PEM type.
     *
     * @param <S> Class type parameter that extends {@code DEREncodable}.
     * @param str the String containing PEM data
     * @param tClass the returned object class that implements
     * {@code DEREncodable}.
     * @return {@code DEREncodable} typecast to {@code tClass}.
     * @throws IllegalArgumentException on error in decoding.
     * @throws ClassCastException if the given class is invalid for the PEM.
     * @throws NullPointerException when any input values are null.
     *
     * @see PEMDecoder for how {@code tClass} can be used.
     */
    public <S extends DEREncodable> S decode(String str, Class<S> tClass) {
        Objects.requireNonNull(str);
        try {
            return decode(new ByteArrayInputStream(
                str.getBytes(StandardCharsets.ISO_8859_1)), tClass);
        } catch (IOException e) {
            // With all data contained in the String, there are no IO ops.
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Decodes and returns the specified class for the given
     * {@link InputStream}.  The class must extend {@link DEREncodable} and be
     * an appropriate class for the PEM type.
     *
     * @param <S> Class type parameter that extends {@code DEREncodable}.
     * @param is an InputStream containing PEM data
     * @param tClass the returned object class that implements
     *   {@code DEREncodable}.
     * @return {@code DEREncodable} typecast to {@code tClass}
     * @throws IOException on IO error with the InputStream.
     * @throws IllegalArgumentException on error in decoding.
     * @throws ClassCastException if the given class is invalid for the PEM.
     * @throws NullPointerException when any input values are null.
     *
     * @see #decode(InputStream)
     * @see #decode(String, Class)
     */
    public <S extends DEREncodable> S decode(InputStream is, Class<S> tClass)
        throws IOException {
        Objects.requireNonNull(is);
        Objects.requireNonNull(tClass);
        PEMRecord pem = Pem.readPEM(is);

        if (tClass.isAssignableFrom(PEMRecord.class)) {
            return tClass.cast(pem);
        }
        DEREncodable so = decode(pem);

        /*
         * If the object is a KeyPair, check if the tClass is set to class
         * specific to a private or public key.  Because PKCS8v2 can be a
         * KeyPair, it is possible for someone to assume all their PEM private
         * keys are only PrivateKey and not KeyPair.
         */
        if (so instanceof KeyPair kp) {
            if ((PrivateKey.class).isAssignableFrom(tClass) ||
                (PKCS8EncodedKeySpec.class).isAssignableFrom(tClass)) {
                so = kp.getPrivate();
            }
            if ((PublicKey.class).isAssignableFrom(tClass) ||
                (X509EncodedKeySpec.class).isAssignableFrom(tClass)) {
                so = kp.getPublic();
            }
        }

        /*
         * KeySpec use getKeySpec after the Key has been generated.  Even though
         * returning a binary encoding after the Base64 decoding is ok when the
         * user wants PKCS8EncodedKeySpec, generating the key verifies the
         * binary encoding and allows the KeyFactory to use the provider's
         * KeySpec()
         */

        if ((EncodedKeySpec.class).isAssignableFrom(tClass) &&
            so instanceof Key key) {
            try {
                // unchecked suppressed as we know tClass comes from KeySpec
                // KeyType not relevant here.  We just want KeyFactory
                if ((PKCS8EncodedKeySpec.class).isAssignableFrom(tClass)) {
                    so = getKeyFactory(key.getAlgorithm()).
                        getKeySpec(key, PKCS8EncodedKeySpec.class);
                } else if ((X509EncodedKeySpec.class).isAssignableFrom(tClass)) {
                    so = getKeyFactory(key.getAlgorithm())
                        .getKeySpec(key, X509EncodedKeySpec.class);
                } else {
                    throw new IllegalArgumentException("Invalid KeySpec.");
                }
            } catch (InvalidKeySpecException e) {
                throw new IllegalArgumentException("Invalid KeySpec " +
                    "specified (" + tClass.getName() +") for key (" +
                    key.getClass().getName() +")", e);
            }
        }

        return tClass.cast(so);
    }

    private KeyFactory getKeyFactory(String algorithm) {
        try {
            if (factory == null) {
                return KeyFactory.getInstance(algorithm);
            }
            return KeyFactory.getInstance(algorithm, factory);
        } catch(GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    // Convenience method to avoid provider getInstance checks clutter
    private CertificateFactory getCertFactory(String algorithm) {
        try {
            if (factory == null) {
                return CertificateFactory.getInstance(algorithm);
            }
            return CertificateFactory.getInstance(algorithm, factory);
        } catch (GeneralSecurityException e) {
            throw new IllegalArgumentException(e);
        }
    }

    /**
     * Configures and returns a new {@code PEMDecoder} instance from the
     * current instance that will use {@link KeyFactory} and
     * {@link CertificateFactory} classes from the specified {@link Provider}.
     * Any errors using the {@code provider} will occur during decoding.
     *
     * <p>If {@code provider} is {@code null}, a new instance is returned with
     * the default provider configuration.
     *
     * @param provider the factory provider
     * @return new configured {@code PEMDecoder} instance
     */
    public PEMDecoder withFactory(Provider provider) {
        return new PEMDecoder(provider, password);
    }

    /**
     * Returns a copy of this PEMDecoder that will decrypt encrypted PEM data
     * such as encrypted private keys with the specified password.
     * Non-encrypted PEM may still be decoded from this instance.
     *
     * @param password the password to decrypt encrypted PEM data.  This array
     *                 is cloned and stored in the new instance.
     * @return new configured {@code PEMDecoder} instance
     * @throws NullPointerException if {@code password} is null.
     */
    public PEMDecoder withDecryption(char[] password) {
        return new PEMDecoder(factory, new PBEKeySpec(password));
    }
}
