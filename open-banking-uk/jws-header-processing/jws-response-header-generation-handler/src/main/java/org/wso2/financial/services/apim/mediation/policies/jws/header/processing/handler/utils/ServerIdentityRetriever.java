/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

package org.wso2.financial.services.apim.mediation.policies.jws.header.processing.handler.utils;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.SynapseException;
import org.wso2.carbon.core.util.KeyStoreManager;

import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.util.Optional;

/**
 * Utility to retrieve Server signing key and certificates.
 * Uses Carbon KeyStoreManager which is HSM-aware - returns PKCS#11 backed
 * keys when HSM is configured, or file-based keys otherwise.
 */
public class ServerIdentityRetriever {

    private static final Log log = LogFactory.getLog(ServerIdentityRetriever.class);

    // Super tenant ID used for KeyStoreManager
    private static final int SUPER_TENANT_ID = -1234;

    // Cached signing key (loaded once)
    private static volatile Key signingKey;

    /**
     * Returns the signing key using Carbon KeyStoreManager.
     * KeyStoreManager is HSM-aware and will return:
     * - PKCS#11 backed key (P11PrivateKey) when HSM is configured
     * - File-based key when HSM is not configured
     *
     * @param alias Alias is ignored - uses default primary key from KeyStoreManager
     * @return Optional containing the signing key
     */
    public static Optional<Key> getSigningKey(String alias) {
        Key localKey = signingKey;

        if (localKey == null) {
            synchronized (ServerIdentityRetriever.class) {
                localKey = signingKey;
                if (localKey == null) {
                    log.debug("Initializing signing key from KeyStoreManager (HSM-aware)");
                    try {
                        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(SUPER_TENANT_ID);
                        localKey = keyStoreManager.getDefaultPrivateKey();
                        signingKey = localKey;

                        log.info("JWS signing key loaded successfully. Key type: " +
                                localKey.getClass().getName());
                    } catch (Exception e) {
                        log.error("Error occurred while retrieving private key from KeyStoreManager", e);
                        throw new SynapseException("Unable to retrieve signing key from KeyStoreManager", e);
                    }
                }
            }
        }
        return Optional.ofNullable(localKey);
    }

    /**
     * Returns the certificate from KeyStoreManager's primary keystore.
     *
     * @param alias Certificate alias to retrieve
     * @return Certificate for the given alias
     * @throws KeyStoreException if certificate cannot be retrieved
     */
    public static Certificate getCertificate(String alias) throws KeyStoreException {

        try {
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(SUPER_TENANT_ID);
            KeyStore keyStore = keyStoreManager.getPrimaryKeyStore();
            return keyStore.getCertificate(alias);
        } catch (Exception e) {
            throw new KeyStoreException("Unable to retrieve certificate from KeyStoreManager", e);
        }
    }
}
