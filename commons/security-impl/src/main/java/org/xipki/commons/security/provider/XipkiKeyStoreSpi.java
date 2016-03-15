/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License (version 3
 * or later at your option) as published by the Free Software Foundation
 * with the addition of the following permission added to Section 15 as
 * permitted in Section 7(a):
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.security.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.security.api.XiSecurityException;
import org.xipki.commons.security.api.SecurityFactory;
import org.xipki.commons.security.api.p11.P11CryptService;
import org.xipki.commons.security.api.p11.P11EntityIdentifier;
import org.xipki.commons.security.api.p11.P11KeyIdentifier;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class XipkiKeyStoreSpi extends KeyStoreSpi {

    private static class MyEnumeration<E> implements Enumeration<E> {

        private Iterator<E> iter;

        MyEnumeration(
                final Iterator<E> iter) {
            this.iter = iter;
        }

        @Override
        public boolean hasMoreElements() {
            return iter.hasNext();
        }

        @Override
        public E nextElement() {
            return iter.next();
        }

    } // class MyEnumeration

    private static class KeyCertEntry {

        private PrivateKey key;

        private Certificate[] chain;

        KeyCertEntry(
                final PrivateKey key,
                final Certificate[] chain) {
            this.key = ParamUtil.requireNonNull("key", key);
            this.chain = ParamUtil.requireNonNull("chain", chain);
            if (chain.length < 1) {
                throw new IllegalArgumentException("chain does not contain any certificate");
            }
        }

        PrivateKey getKey() {
            return key;
        }

        Certificate[] getCertificateChain() {
            return Arrays.copyOf(chain, chain.length);
        }

        Certificate getCertificate() {
            return chain[0];
        }

    } // class KeyCertEntry

    private static SecurityFactory securityFactory;

    private Date creationDate;

    private Map<String, KeyCertEntry> keyCerts = new HashMap<>();

    @Override
    public void engineLoad(
            final InputStream stream,
            final char[] password)
    throws IOException, NoSuchAlgorithmException, CertificateException {
        this.creationDate = new Date();

        try {
            P11CryptService p11Servcie = securityFactory.getP11CryptService(
                    SecurityFactory.DEFAULT_P11MODULE_NAME);
            P11SlotIdentifier[] slotIds = p11Servcie.getSlotIdentifiers();

            Map<P11SlotIdentifier, String[]> keyLabelsMap = new HashMap<>();

            Set<String> allKeyLabels = new HashSet<>();
            Set<String> duplicatedKeyLabels = new HashSet<>();

            for (P11SlotIdentifier slotId: slotIds) {
                String[] keyLabels = p11Servcie.getKeyLabels(slotId);
                for (String keyLabel : keyLabels) {
                    if (allKeyLabels.contains(keyLabel)) {
                        duplicatedKeyLabels.add(keyLabel);
                    }
                    allKeyLabels.add(keyLabel);
                }

                keyLabelsMap.put(slotId, keyLabels);
            } // end for

            for (P11SlotIdentifier slotId: slotIds) {
                String[] keyLabels = keyLabelsMap.get(slotId);
                for (String keyLabel : keyLabels) {
                    String alias = keyLabel;
                    if (duplicatedKeyLabels.contains(keyLabel)) {
                        alias += "-slot" + slotId.getSlotIndex();
                    }

                    P11KeyIdentifier keyId = new P11KeyIdentifier(keyLabel);
                    P11EntityIdentifier entityId = new P11EntityIdentifier(slotId, keyId);
                    X509Certificate[] chain = p11Servcie.getCertificates(entityId);
                    if (chain != null && chain.length > 0) {
                        P11PrivateKey key = new P11PrivateKey(p11Servcie, entityId);

                        KeyCertEntry keyCertEntry = new KeyCertEntry(key, chain);
                        keyCerts.put(alias, keyCertEntry);
                    }
                } // end for
            } // end for
        } catch (XiSecurityException | P11TokenException ex) {
            throw new IllegalArgumentException(ex.getClass().getName() + ": " + ex.getMessage(),
                    ex);
        }
    } // method engineLoad

    @Override
    public void engineStore(
            final OutputStream stream,
            final char[] password)
    throws IOException, NoSuchAlgorithmException, CertificateException {
    }

    @Override
    public Key engineGetKey(
            final String alias,
            final char[] password)
    throws NoSuchAlgorithmException, UnrecoverableKeyException {
        if (!keyCerts.containsKey(alias)) {
            return null;
        }

        return keyCerts.get(alias).getKey();
    }

    @Override
    public Certificate[] engineGetCertificateChain(
            final String alias) {
        if (!keyCerts.containsKey(alias)) {
            return null;
        }

        return keyCerts.get(alias).getCertificateChain();
    }

    @Override
    public Certificate engineGetCertificate(
            final String alias) {
        if (!keyCerts.containsKey(alias)) {
            return null;
        }

        return keyCerts.get(alias).getCertificate();
    }

    @Override
    public Date engineGetCreationDate(
            final String alias) {
        if (!keyCerts.containsKey(alias)) {
            return null;
        }
        return creationDate;
    }

    @Override
    public void engineSetKeyEntry(
            final String alias,
            final Key key,
            final char[] password,
            final Certificate[] chain)
    throws KeyStoreException {
        throw new KeyStoreException("keystore is read only");
    }

    @Override
    public void engineSetKeyEntry(
            final String alias,
            final byte[] key,
            final Certificate[] chain)
    throws KeyStoreException {
        throw new KeyStoreException("keystore is read only");
    }

    @Override
    public void engineSetCertificateEntry(
            final String alias,
            final Certificate cert)
    throws KeyStoreException {
        throw new KeyStoreException("keystore is read only");
    }

    @Override
    public void engineDeleteEntry(
            final String alias)
    throws KeyStoreException {
        throw new KeyStoreException("keystore is read only");
    }

    @Override
    public Enumeration<String> engineAliases() {
        return new MyEnumeration<>(keyCerts.keySet().iterator());
    }

    @Override
    public boolean engineContainsAlias(
            final String alias) {
        return keyCerts.containsKey(alias);
    }

    @Override
    public int engineSize() {
        return keyCerts.size();
    }

    @Override
    public boolean engineIsKeyEntry(
            final String alias) {
        if (!keyCerts.containsKey(alias)) {
            return false;
        }

        return keyCerts.get(alias).key != null;
    }

    @Override
    public boolean engineIsCertificateEntry(
            final String alias) {
        if (!keyCerts.containsKey(alias)) {
            return false;
        }

        return keyCerts.get(alias).key == null;
    }

    @Override
    public String engineGetCertificateAlias(
            final Certificate cert) {
        for (String alias : keyCerts.keySet()) {
            if (keyCerts.get(alias).getCertificate().equals(cert)) {
                return alias;
            }
        }

        return null;
    }

    public static void setSecurityFactory(
            final SecurityFactory pSecurityFactory) { // CHECKSTYLE:SKIP
        securityFactory = pSecurityFactory;
    }

}
