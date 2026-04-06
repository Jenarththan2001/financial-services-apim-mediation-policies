/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com).
 * <p>
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 *     http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.financial.services.apim.mediation.policies.jwe.processing.util;

import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

/**
 * Unit tests for HsmJweDecryptionHelper.
 * <p>
 * Tests the custom JWE decryption logic (raw RSA + OAEP unpadding + AES-GCM) using a standard
 * Java RSA provider instead of a real PKCS#11 HSM. This is possible because the package-private
 * overload {@code decryptWithHSM(parsedJwt, privateKey, rsaProvider)} accepts any RSA-capable
 * provider — the mathematical operations are identical regardless of provider.
 */
public class HsmJweDecryptionHelperTest {

    private static final String KEYSTORE_PATH = "src/test/resources/wso2carbon.jks";
    private static final String KEYSTORE_PASSWORD = "wso2carbon";
    private static final String KEY_ALIAS = "wso2carbon";

    private PrivateKey privateKey;
    private RSAPublicKey publicKey;
    private Provider rsaProvider;
    private int keyBitLength;

    @BeforeClass
    public void setup() throws Exception {

        // Load keys from test keystore
        KeyStore ks = KeyStore.getInstance("JKS");
        try (FileInputStream fis = new FileInputStream(KEYSTORE_PATH)) {
            ks.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }
        privateKey = (PrivateKey) ks.getKey(KEY_ALIAS, KEYSTORE_PASSWORD.toCharArray());
        Certificate cert = ks.getCertificate(KEY_ALIAS);
        publicKey = (RSAPublicKey) cert.getPublicKey();
        keyBitLength = publicKey.getModulus().bitLength();

        // Find the default provider that handles RSA/ECB/NoPadding (typically SunJCE in Java 17)
        rsaProvider = Cipher.getInstance("RSA/ECB/NoPadding").getProvider();
    }

    // ==================== Data Providers ====================

    @DataProvider(name = "allAlgorithmCombinations")
    public Object[][] allAlgorithmCombinations() {

        return new Object[][]{
                {"RSA-OAEP-256", "A128GCM"}, {"RSA-OAEP-256", "A192GCM"}, {"RSA-OAEP-256", "A256GCM"},
                {"RSA-OAEP", "A128GCM"}, {"RSA-OAEP", "A192GCM"}, {"RSA-OAEP", "A256GCM"},
                {"RSA-OAEP-384", "A128GCM"}, {"RSA-OAEP-384", "A192GCM"}, {"RSA-OAEP-384", "A256GCM"},
                {"RSA-OAEP-512", "A128GCM"}, {"RSA-OAEP-512", "A192GCM"}, {"RSA-OAEP-512", "A256GCM"},
                {"RSA1_5", "A128GCM"}, {"RSA1_5", "A192GCM"}, {"RSA1_5", "A256GCM"}
        };
    }

    @DataProvider(name = "oaepAlgorithmsOnly")
    public Object[][] oaepAlgorithmsOnly() {

        return new Object[][]{
                {"RSA-OAEP-256", "A256GCM"},
                {"RSA-OAEP", "A256GCM"},
                {"RSA-OAEP-384", "A256GCM"},
                {"RSA-OAEP-512", "A256GCM"}
        };
    }

    // ==================== Full End-to-End Decryption Tests ====================

    @Test(dataProvider = "allAlgorithmCombinations")
    public void testDecryptWithHSM_AllCombinations(String encAlg, String encMethod) throws Exception {

        // Encrypt a JWE token using Nimbus (same approach as existing tests)
        String jweToken = JweProcessingTestUtil.encryptPayload(encAlg, encMethod,
                JweProcessingTestConstants.PAYLOAD);
        Assert.assertNotNull(jweToken, "Encrypted payload should not be null for " + encAlg + "+" + encMethod);

        EncryptedJWT parsedJwt = EncryptedJWT.parse(jweToken);

        // Decrypt using the package-private overload with a standard Java RSA provider
        JWTClaimsSet result = HsmJweDecryptionHelper.decryptWithHSM(parsedJwt, privateKey, rsaProvider);

        Assert.assertNotNull(result, "Decrypted claims should not be null for " + encAlg + "+" + encMethod);
        Assert.assertNotNull(result.getJSONObjectClaim("Data"),
                "Data claim should exist in decrypted payload");
        Assert.assertNotNull(result.getClaim("Risk"),
                "Risk claim should exist in decrypted payload");
    }

    @Test(expectedExceptions = GeneralSecurityException.class,
            expectedExceptionsMessageRegExp = ".*Could not find SunPKCS11 provider.*")
    public void testDecryptWithHSM_NonP11Key_ThrowsOnProviderLookup() throws Exception {

        // Use the public method (2-arg) with a non-P11 key — should throw because no SunPKCS11 provider
        String jweToken = JweProcessingTestUtil.encryptPayload("RSA-OAEP-256", "A256GCM",
                JweProcessingTestConstants.PAYLOAD);
        EncryptedJWT parsedJwt = EncryptedJWT.parse(jweToken);

        HsmJweDecryptionHelper.decryptWithHSM(parsedJwt, privateKey);
    }

    // ==================== validateAlgorithm Tests ====================

    @Test(dataProvider = "allAlgorithmCombinations")
    public void testValidateAlgorithm_SupportedCombinations(String encAlgStr, String encMethodStr)
            throws Exception {

        JWEAlgorithm alg = JWEAlgorithm.parse(encAlgStr);
        EncryptionMethod enc = EncryptionMethod.parse(encMethodStr);
        // Should not throw for any supported combination
        HsmJweDecryptionHelper.validateAlgorithm(alg, enc);
    }

    @Test(expectedExceptions = GeneralSecurityException.class,
            expectedExceptionsMessageRegExp = ".*Unsupported JWE key encryption algorithm.*")
    public void testValidateAlgorithm_UnsupportedKeyAlgorithm() throws Exception {

        HsmJweDecryptionHelper.validateAlgorithm(JWEAlgorithm.A128KW, EncryptionMethod.A256GCM);
    }

    @Test(expectedExceptions = GeneralSecurityException.class,
            expectedExceptionsMessageRegExp = ".*Unsupported JWE content encryption method.*")
    public void testValidateAlgorithm_UnsupportedEncMethod() throws Exception {

        HsmJweDecryptionHelper.validateAlgorithm(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A128CBC_HS256);
    }

    // ==================== getOAEPHashAlgorithm Tests ====================

    @Test
    public void testGetOAEPHashAlgorithm_RSA_OAEP_256() {

        Assert.assertEquals(HsmJweDecryptionHelper.getOAEPHashAlgorithm(JWEAlgorithm.RSA_OAEP_256), "SHA-256");
    }

    @Test
    public void testGetOAEPHashAlgorithm_RSA_OAEP_384() {

        Assert.assertEquals(HsmJweDecryptionHelper.getOAEPHashAlgorithm(JWEAlgorithm.RSA_OAEP_384), "SHA-384");
    }

    @Test
    public void testGetOAEPHashAlgorithm_RSA_OAEP_512() {

        Assert.assertEquals(HsmJweDecryptionHelper.getOAEPHashAlgorithm(JWEAlgorithm.RSA_OAEP_512), "SHA-512");
    }

    @Test
    public void testGetOAEPHashAlgorithm_RSA_OAEP_DefaultSHA1() {

        Assert.assertEquals(HsmJweDecryptionHelper.getOAEPHashAlgorithm(JWEAlgorithm.RSA_OAEP), "SHA-1");
    }

    // ==================== xor Tests ====================

    @Test
    public void testXor_BasicOperation() {

        byte[] a = new byte[]{0x0F, 0x00, (byte) 0xFF, 0x55};
        byte[] b = new byte[]{(byte) 0xF0, (byte) 0xFF, (byte) 0xFF, (byte) 0xAA};
        byte[] result = HsmJweDecryptionHelper.xor(a, b);
        Assert.assertEquals(result, new byte[]{(byte) 0xFF, (byte) 0xFF, 0x00, (byte) 0xFF});
    }

    @Test
    public void testXor_SameInputProducesZeros() {

        byte[] a = new byte[]{0x12, 0x34, 0x56, 0x78};
        byte[] result = HsmJweDecryptionHelper.xor(a, a);
        Assert.assertEquals(result, new byte[]{0x00, 0x00, 0x00, 0x00});
    }

    @Test
    public void testXor_WithZerosIsIdentity() {

        byte[] a = new byte[]{0x12, 0x34, 0x56, 0x78};
        byte[] zeros = new byte[]{0x00, 0x00, 0x00, 0x00};
        byte[] result = HsmJweDecryptionHelper.xor(a, zeros);
        Assert.assertEquals(result, a);
    }

    // ==================== mgf1 Tests ====================

    @Test
    public void testMgf1_OutputLength() throws Exception {

        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] seed = "test seed for MGF1".getBytes();

        byte[] mask32 = HsmJweDecryptionHelper.mgf1(seed, 32, md);
        Assert.assertEquals(mask32.length, 32, "MGF1 should produce exactly 32 bytes");

        md.reset();
        byte[] mask64 = HsmJweDecryptionHelper.mgf1(seed, 64, md);
        Assert.assertEquals(mask64.length, 64, "MGF1 should produce exactly 64 bytes");

        md.reset();
        byte[] mask100 = HsmJweDecryptionHelper.mgf1(seed, 100, md);
        Assert.assertEquals(mask100.length, 100, "MGF1 should produce exactly 100 bytes");
    }

    @Test
    public void testMgf1_Deterministic() throws Exception {

        byte[] seed = "deterministic test seed".getBytes();

        MessageDigest md1 = MessageDigest.getInstance("SHA-256");
        byte[] mask1 = HsmJweDecryptionHelper.mgf1(seed, 48, md1);

        MessageDigest md2 = MessageDigest.getInstance("SHA-256");
        byte[] mask2 = HsmJweDecryptionHelper.mgf1(seed, 48, md2);

        Assert.assertEquals(mask1, mask2, "MGF1 with same seed and length should produce identical output");
    }

    @Test
    public void testMgf1_DifferentSeedsProduceDifferentOutput() throws Exception {

        byte[] seed1 = "seed one".getBytes();
        byte[] seed2 = "seed two".getBytes();

        MessageDigest md1 = MessageDigest.getInstance("SHA-256");
        byte[] mask1 = HsmJweDecryptionHelper.mgf1(seed1, 32, md1);

        MessageDigest md2 = MessageDigest.getInstance("SHA-256");
        byte[] mask2 = HsmJweDecryptionHelper.mgf1(seed2, 32, md2);

        Assert.assertNotEquals(mask1, mask2, "MGF1 with different seeds should produce different output");
    }

    // ==================== oaepUnpad Tests ====================

    @Test
    public void testOaepUnpad_DirectRecovery_SHA256() throws Exception {

        // Create random test data (simulating a 256-bit CEK for A256GCM)
        byte[] originalData = new byte[32];
        new SecureRandom().nextBytes(originalData);

        // Encrypt with OAEP using SHA-256 for both hash and MGF1 (matches RSA-OAEP-256 per RFC 7518)
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1",
                new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        Cipher oaepCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        oaepCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec);
        byte[] encrypted = oaepCipher.doFinal(originalData);

        // Raw RSA decrypt (no padding) — simulates what the HSM does
        Cipher rawCipher = Cipher.getInstance("RSA/ECB/NoPadding", rsaProvider);
        rawCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] rawDecrypted = rawCipher.doFinal(encrypted);

        // Our manual OAEP unpadding should recover the original data
        byte[] recovered = HsmJweDecryptionHelper.oaepUnpad(rawDecrypted, "SHA-256", keyBitLength);
        Assert.assertEquals(recovered, originalData,
                "OAEP unpad with SHA-256 should recover the original CEK");
    }

    @Test
    public void testOaepUnpad_DirectRecovery_SHA1() throws Exception {

        // Create random test data (simulating a 128-bit CEK for A128GCM)
        byte[] originalData = new byte[16];
        new SecureRandom().nextBytes(originalData);

        // RSA-OAEP uses SHA-1 for both hash and MGF1
        OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-1", "MGF1",
                new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT);
        Cipher oaepCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        oaepCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec);
        byte[] encrypted = oaepCipher.doFinal(originalData);

        Cipher rawCipher = Cipher.getInstance("RSA/ECB/NoPadding", rsaProvider);
        rawCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] rawDecrypted = rawCipher.doFinal(encrypted);

        byte[] recovered = HsmJweDecryptionHelper.oaepUnpad(rawDecrypted, "SHA-1", keyBitLength);
        Assert.assertEquals(recovered, originalData,
                "OAEP unpad with SHA-1 should recover the original CEK");
    }

    @Test
    public void testOaepUnpad_WithLeadingZerosStripped() throws Exception {

        // This tests the SunPKCS11 behavior where raw RSA output may have leading zeros stripped.
        // Our oaepUnpad re-pads with leading zeros to handle this.
        byte[] originalData = new byte[32];
        new SecureRandom().nextBytes(originalData);

        OAEPParameterSpec oaepSpec = new OAEPParameterSpec("SHA-256", "MGF1",
                new MGF1ParameterSpec("SHA-256"), PSource.PSpecified.DEFAULT);
        Cipher oaepCipher = Cipher.getInstance("RSA/ECB/OAEPPadding");
        oaepCipher.init(Cipher.ENCRYPT_MODE, publicKey, oaepSpec);
        byte[] encrypted = oaepCipher.doFinal(originalData);

        Cipher rawCipher = Cipher.getInstance("RSA/ECB/NoPadding", rsaProvider);
        rawCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] rawDecrypted = rawCipher.doFinal(encrypted);

        // OAEP encoded message always starts with 0x00 — strip it to simulate SunPKCS11 behavior
        if (rawDecrypted.length > 0 && rawDecrypted[0] == 0) {
            byte[] stripped = new byte[rawDecrypted.length - 1];
            System.arraycopy(rawDecrypted, 1, stripped, 0, stripped.length);

            byte[] recovered = HsmJweDecryptionHelper.oaepUnpad(stripped, "SHA-256", keyBitLength);
            Assert.assertEquals(recovered, originalData,
                    "OAEP unpad should handle stripped leading zeros (SunPKCS11 behavior)");
        }
    }

    @Test(expectedExceptions = GeneralSecurityException.class,
            expectedExceptionsMessageRegExp = ".*first byte is not 0x00.*")
    public void testOaepUnpad_InvalidFirstByte() throws Exception {

        int k = keyBitLength / 8;
        byte[] invalidEM = new byte[k];
        // Fill with random data then set first byte to non-zero
        new SecureRandom().nextBytes(invalidEM);
        invalidEM[0] = 0x01;

        HsmJweDecryptionHelper.oaepUnpad(invalidEM, "SHA-256", keyBitLength);
    }

    // ==================== getHSMProvider Tests ====================

    @Test
    public void testGetHSMProvider_NonP11Key_ReturnsNull() {

        // A standard JKS RSAPrivateCrtKeyImpl should not find an HSM provider
        Provider result = HsmJweDecryptionHelper.getHSMProvider(privateKey);
        Assert.assertNull(result, "Non-P11 key should return null (no SunPKCS11 provider)");
    }
}
