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
 * @run main PEMMultiThreadTest
 */

import java.security.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PEMMultiThreadTest {
    static final int THREAD_COUNT = 5;
    static final int KEYS_COUNT = 50;

    public static void main(String[] args) throws Exception {
        PEMEncoder encoder = PEMEncoder.of();
        try(ExecutorService ex = Executors.newFixedThreadPool(THREAD_COUNT)) {
            List<PublicKey> keys = new ArrayList<>();
            List<String> encoded = Collections.synchronizedList(new ArrayList<>());
            List<String> decoded = Collections.synchronizedList(new ArrayList<>());
            final CountDownLatch encodingComplete = new CountDownLatch(KEYS_COUNT);
            final CountDownLatch decodingComplete = new CountDownLatch(KEYS_COUNT);

            for (int i = 0 ; i < KEYS_COUNT ; i++) {
                KeyPair kp = getKeyPair();
                keys.add(kp.getPublic());
                ex.submit(() -> {
                    encoded.add(encoder.encodeToString(kp.getPublic()));
                    encodingComplete.countDown();
                });
            }
            encodingComplete.await();

            PEMDecoder decoder = PEMDecoder.of();
            for (String pem : encoded) {
                ex.submit(() -> {
                    decoded.add(decoder.decode(pem, PublicKey.class).toString());
                    decodingComplete.countDown();
                });
            }

            decodingComplete.await();

            // verify all keys were properly encoded and decoded comparing with the original list
            for (PublicKey kp : keys) {
                if (!decoded.contains(kp.toString())) {
                    throw new RuntimeException("a key was not properly encoded and decoded: " + decoded);
                }
                // to avoid duplication
                decoded.remove(kp.toString());
            }
        }

        System.out.println("PASS: testThreadSafety");
    }

    private static KeyPair getKeyPair() throws NoSuchAlgorithmException {
        String alg = "EC";
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(alg);
        kpg.initialize(jdk.test.lib.security.SecurityUtils.getTestKeySize(alg));
        return kpg.generateKeyPair();
    }
}
