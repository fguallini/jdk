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

/*
 * @test
 * @bug 8298420
 * @library /test/lib
 * @summary Testing basic PEM API encoding
 * @enablePreview
 * @modules java.base/sun.security.util
 * @run main PEMEncoderTest PBEWithHmacSHA256AndAES_128
 * @run main/othervm -Djava.security.properties=${test.src}/java.security-extra
 *      PEMEncoderTest PBEWithHmacSHA512AndAES_256
 */

import sun.security.util.Pem;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.crypto.spec.PBEParameterSpec;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.regex.Pattern;

import jdk.test.lib.security.SecurityUtils;

import static jdk.test.lib.Asserts.assertEquals;
import static jdk.test.lib.Asserts.assertThrows;

public class PEMEncoderTest {

    static Map<String, DEREncodable> keymap;
    static String pkcs8DefaultAlgExpect;
    final static Pattern CR = Pattern.compile("\r");
    final static Pattern LF = Pattern.compile("\n");
    final static Pattern LSDEFAULT = Pattern.compile(System.lineSeparator());


    public static void main(String[] args) throws Exception {
        pkcs8DefaultAlgExpect = args[0];
        PEMEncoder encoder = PEMEncoder.of();

        // These entries are removed
        var newEntryList = new ArrayList<>(PEMData.entryList);
        newEntryList.remove(PEMData.getEntry("rsaOpenSSL"));
        newEntryList.remove(PEMData.getEntry("ecsecp256"));
        newEntryList.remove(PEMData.getEntry("ecsecp384"));
        keymap = generateObjKeyMap(newEntryList);
        System.out.println("Same instance re-encode test:");
        keymap.keySet().stream().forEach(key -> test(key, encoder));
        System.out.println("New instance re-encode test:");
        keymap.keySet().stream().forEach(key -> test(key, PEMEncoder.of()));
        System.out.println("Same instance re-encode testToString:");
        keymap.keySet().stream().forEach(key -> testToString(key, encoder));
        System.out.println("New instance re-encode testToString:");
        keymap.keySet().stream().forEach(key -> testToString(key,
            PEMEncoder.of()));
        System.out.println("Same instance Encoder testEncodedKeySpec:");
        testEncodedKeySpec(encoder);
        System.out.println("New instance Encoder testEncodedKeySpec:");
        testEncodedKeySpec(PEMEncoder.of());
        System.out.println("Same instance Encoder testEmptyKey:");
        testEmptyAndNullKey(encoder);
        keymap = generateObjKeyMap(PEMData.encryptedList);
        System.out.println("Same instance Encoder match test, no provider and with Algo :");
        keymap.keySet().stream().forEach(key -> testEncryptedMatch(key, encoder, false, true));
        System.out.println("Same instance Encoder match test, no provider and no algo :");
        keymap.keySet().stream().forEach(key -> testEncryptedMatch(key, encoder, false, false));
        System.out.println("Same instance Encoder match test, with provider :");
        keymap.keySet().stream().filter(key -> "SUN".equals( PEMData.getEntry(key).provider()))
                .forEach(key -> testEncryptedMatch(key, encoder, true, false));
        System.out.println("Same instance Encoder new withEnc test:");
        keymap.keySet().stream().forEach(key -> testEncrypted(key, encoder));
        System.out.println("New instance Encoder and withEnc test:");
        keymap.keySet().stream().forEach(key -> testEncrypted(key, PEMEncoder.of()));
        System.out.println("Same instance encrypted Encoder test:");
        PEMEncoder encEncoder = encoder.withEncryption("fish".toCharArray());
        keymap.keySet().stream().forEach(key -> testSameEncryptor(key, encEncoder));
        try {
            encoder.withEncryption(null);
        } catch (Exception e) {
            if (!(e instanceof NullPointerException)) {
                throw new Exception("Should have been a NullPointerException thrown");
            }
        }
    }

    static Map generateObjKeyMap(List<PEMData.Entry> list) {
        Map<String, DEREncodable> keymap = new HashMap<>();
        PEMDecoder pemd = PEMDecoder.of();
        for (PEMData.Entry entry : list) {
            try {
                if (entry.password() != null) {
                    keymap.put(entry.name(), pemd.withDecryption(
                        entry.password()).decode(entry.pem()));
                } else {
                    keymap.put(entry.name(), pemd.decode(entry.pem(),
                        entry.clazz()));
                }
            } catch (Exception e) {
                System.err.println("Verify PEMDecoderTest passes before " +
                    "debugging this test.");
                throw new AssertionError("Failed to initialize map on" +
                    " entry \"" + entry.name() + "\"", e);
            }
        }
        return keymap;
    }

    static void test(String key, PEMEncoder encoder) {
        byte[] result;
        PEMData.Entry entry = PEMData.getEntry(key);
        try {
            result = encoder.encode(keymap.get(key));
        } catch (RuntimeException e) {
            throw new AssertionError("Encoder use failure with " +
                entry.name(), e);
        }

        checkResults(entry, new String(result, StandardCharsets.UTF_8));
        System.out.println("PASS: " + entry.name());
    }

    static void testToString(String key, PEMEncoder encoder) {
        String result;
        PEMData.Entry entry = PEMData.getEntry(key);
        try {
            result = encoder.encodeToString(keymap.get(key));
        } catch (RuntimeException e) {
            throw new AssertionError("Encoder use failure with " +
                entry.name(), e);
        }

        checkResults(entry, result);
        System.out.println("PASS: " + entry.name());
    }

    /*
     Test cannot verify PEM was the same as known PEM because we have no
     public access to the AlgoritmID.params and PBES2Parameters.
     */
    static void testEncrypted(String key, PEMEncoder encoder) {
        PEMData.Entry entry = PEMData.getEntry(key);
        try {
            String pem = encoder.withEncryption(
                    (entry.password() != null ? entry.password() :
                        "fish".toCharArray()))
                .encodeToString(keymap.get(key));

            verifyEncriptionAlg(pem);
        } catch (RuntimeException e) {
            throw new AssertionError("Encrypted encoder failed with " +
                entry.name(), e);
        }

        System.out.println("PASS: " + entry.name());
    }

    private static void verifyEncriptionAlg(String pem) {
        var epki = PEMDecoder.of().decode(pem, EncryptedPrivateKeyInfo.class);
        assertEquals(epki.getAlgName(), pkcs8DefaultAlgExpect);
    }

    /*
     Test cannot verify PEM was the same as known PEM because we have no
     public access to the AlgoritmID.params and PBES2Parameters.
     */
    static void testSameEncryptor(String key, PEMEncoder encoder) {
        PEMData.Entry entry = PEMData.getEntry(key);
        try {
            encoder.encodeToString(keymap.get(key));
        } catch (RuntimeException e) {
            throw new AssertionError("Encrypted encoder failured with " +
                entry.name(), e);
        }

        System.out.println("PASS: " + entry.name());
    }

    static void testEncryptedMatch(String key, PEMEncoder encoder, boolean withProvider, boolean withAlgo) {
        String result;
        PEMData.Entry entry = PEMData.getEntry(key);
        Provider provider = withProvider ? Security.getProvider(entry.provider()) : null;

        try {
            PrivateKey pkey = (PrivateKey) keymap.get(key);
            EncryptedPrivateKeyInfo ekpi = PEMDecoder.of().decode(entry.pem(),
                EncryptedPrivateKeyInfo.class);
            if (entry.password() != null) {
                if (withAlgo) {
                    EncryptedPrivateKeyInfo.encryptKey(pkey, entry.password(),
                            Pem.DEFAULT_ALGO, ekpi.getAlgParameters().
                                    getParameterSpec(PBEParameterSpec.class),
                            provider);
                } else {
                    EncryptedPrivateKeyInfo.encryptKey(pkey, entry.password());
                }
            }
            result = encoder.encodeToString(ekpi);
        } catch (RuntimeException | InvalidParameterSpecException e) {
            throw new AssertionError("Encrypted encoder failure with " +
                entry.name(), e);
        }

        checkResults(entry, result);
        System.out.println("PASS: " + entry.name());
    }

    static void checkResults(PEMData.Entry entry, String result) {
        String pem = new String(entry.pem());
        // The below matches the \r\n generated PEM with the PEM passed
        // into the test.
        pem = CR.matcher(pem).replaceAll("");
        pem = LF.matcher(pem).replaceAll("");
        result = LSDEFAULT.matcher(result).replaceAll("");
        try {
            if (pem.compareTo(result) != 0) {
                System.out.println("expected:\n" + pem);
                System.out.println("generated:\n" + result);
                indexDiff(pem, result);
            }
        } catch (AssertionError e) {
            throw new AssertionError("Encoder PEM mismatch " +
                entry.name(), e);
        }
    }

    static void indexDiff(String a, String b) {
        String lenerr = "";
        int len = a.length();
        int lenb = b.length();
        if (len != lenb) {
            lenerr = ":  Length mismatch: " + len + " vs " + lenb;
            len = Math.min(len, lenb);
        }
        for (int i = 0; i < len; i++) {
            if (a.charAt(i) != b.charAt(i)) {
                throw new AssertionError("Char mistmatch, index #" + i +
                    "  (" + a.charAt(i) + " vs " + b.charAt(i) + ")" + lenerr);
            }
        }
    }
    static void testEncodedKeySpec(PEMEncoder encoder) throws NoSuchAlgorithmException {
        KeyPair kp = getKeyPair();
        encoder.encodeToString(new X509EncodedKeySpec(kp.getPublic().getEncoded()));
        encoder.encodeToString((new PKCS8EncodedKeySpec(kp.getPrivate().getEncoded())));
        System.out.println("PASS: testEncodedKeySpec");
    }

    private static void testEmptyAndNullKey(PEMEncoder encoder) throws NoSuchAlgorithmException {
        KeyPair kp = getKeyPair();
        assertThrows(IllegalArgumentException.class,() -> encoder.encode(
                new KeyPair(kp.getPublic(), new EmptyKey())));
        assertThrows(IllegalArgumentException.class,() -> encoder.encode(
                new KeyPair(kp.getPublic(), null)));

        assertThrows(IllegalArgumentException.class,() -> encoder.encode(
                new KeyPair(new EmptyKey(), kp.getPrivate())));
        assertThrows(IllegalArgumentException.class,() -> encoder.encode(
                new KeyPair(null, kp.getPrivate())));
        System.out.println("PASS: testEmptyKey");
    }

    private static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        Provider provider = Security.getProvider("SunRsaSign");
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", provider);
        kpg.initialize(SecurityUtils.getTestKeySize("RSA"));
        return kpg.generateKeyPair();
    }

    private static class EmptyKey implements PublicKey, PrivateKey {
        @Override
        public String getAlgorithm() { return "Test"; }

        @Override
        public String getFormat() { return "Test"; }

        @Override
        public byte[] getEncoded() { return new byte[0]; }
    }
}
