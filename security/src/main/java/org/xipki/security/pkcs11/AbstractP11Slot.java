/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
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

package org.xipki.security.pkcs11;

import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.DSAParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.util.encoders.Hex;
import org.eclipse.jdt.annotation.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.common.util.LogUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.security.HashAlgoType;
import org.xipki.security.X509Cert;
import org.xipki.security.exception.P11DuplicateEntityException;
import org.xipki.security.exception.P11PermissionException;
import org.xipki.security.exception.P11TokenException;
import org.xipki.security.exception.P11UnknownEntityException;
import org.xipki.security.exception.P11UnsupportedMechanismException;
import org.xipki.security.util.AlgorithmUtil;
import org.xipki.security.util.DSAParameterCache;
import org.xipki.security.util.X509Util;

import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class AbstractP11Slot implements P11Slot {

    private static final Logger LOG = LoggerFactory.getLogger(AbstractP11Slot.class);

    protected final String moduleName;

    protected final P11SlotIdentifier slotId;

    private final boolean readOnly;

    private final SecureRandom random = new SecureRandom();

    private final ConcurrentHashMap<P11ObjectIdentifier, P11Identity> identities =
            new ConcurrentHashMap<>();

    private final ConcurrentHashMap<P11ObjectIdentifier, X509Cert> certificates =
            new ConcurrentHashMap<>();

    private final Set<Long> mechanisms = new HashSet<>();

    private final P11MechanismFilter mechanismFilter;

    protected AbstractP11Slot(final String moduleName, final P11SlotIdentifier slotId,
            final boolean readOnly, final P11MechanismFilter mechanismFilter)
            throws P11TokenException {
        this.mechanismFilter = ParamUtil.requireNonNull("mechanismFilter", mechanismFilter);
        this.moduleName = ParamUtil.requireNonBlank("moduleName", moduleName);
        this.slotId = ParamUtil.requireNonNull("slotId", slotId);
        this.readOnly = readOnly;
    }

    protected static String hex(@NonNull final byte[] bytes) {
        return Hex.toHexString(bytes).toUpperCase();
    }

    protected static String getDescription(final byte[] keyId, final char[] keyLabel) {
        StringBuilder sb = new StringBuilder();
        sb.append("id ").append((keyId == null) ? "null" : Hex.toHexString(keyId));
        sb.append(" and label ").append((keyLabel == null) ? "null" : new String(keyLabel));
        return sb.toString();
    }

    protected static String getDescription(final byte[] keyId, final String keyLabel) {
        StringBuilder sb = new StringBuilder();
        sb.append("id ").append((keyId == null) ? "null" : Hex.toHexString(keyId));
        sb.append(" and label ").append(keyLabel);
        return sb.toString();
    }

    protected abstract void updateCertificate0(final P11ObjectIdentifier objectId,
            final X509Certificate newCert) throws P11TokenException, CertificateException;

    protected abstract void removeIdentity0(P11ObjectIdentifier objectId) throws P11TokenException;

    protected abstract void addCert0(@NonNull final P11ObjectIdentifier objectId,
            @NonNull final X509Certificate cert) throws P11TokenException, CertificateException;

    protected abstract P11Identity generateSecretKey0(long keyType, int keysize,
            @NonNull String label, @NonNull P11NewKeyControl control) throws P11TokenException;

    protected abstract P11Identity createSecretKey0(long keyType, byte[] keyValue,
            @NonNull String label, @NonNull P11NewKeyControl control) throws P11TokenException;

    // CHECKSTYLE:OFF
    protected abstract P11Identity generateDSAKeypair0(final BigInteger p, final BigInteger q,
            final BigInteger g, @NonNull final String label, @NonNull P11NewKeyControl control)
            throws P11TokenException;
    // CHECKSTYLE:ON

    // CHECKSTYLE:SKIP
    protected abstract P11Identity generateECKeypair0(@NonNull ASN1ObjectIdentifier curveId,
            @NonNull String label, @NonNull P11NewKeyControl control) throws P11TokenException;

    // CHECKSTYLE:SKIP
    protected abstract P11Identity generateRSAKeypair0(int keysize,
            @NonNull BigInteger publicExponent, @NonNull String label,
            @NonNull P11NewKeyControl control) throws P11TokenException;

    protected abstract P11SlotRefreshResult refresh0()
            throws P11TokenException;

    protected abstract void removeCerts0(final P11ObjectIdentifier objectId)
            throws P11TokenException;

    protected X509Cert getCertForId(@NonNull final byte[] id) {
        for (P11ObjectIdentifier objId : certificates.keySet()) {
            if (objId.matchesId(id)) {
                return certificates.get(objId);
            }
        }
        return null;
    }

    private void updateCaCertsOfIdentities() {
        for (P11Identity identity : identities.values()) {
            updateCaCertsOfIdentity(identity);
        }
    }

    private void updateCaCertsOfIdentity(@NonNull final P11Identity identity) {
        X509Certificate[] certchain = identity.certificateChain();
        if (certchain == null || certchain.length == 0) {
            return;
        }

        X509Certificate[] newCertchain = buildCertPath(certchain[0]);
        if (!Arrays.equals(certchain, newCertchain)) {
            try {
                identity.setCertificates(newCertchain);
            } catch (P11TokenException ex) {
                LOG.warn("could not set certificates for identity {}", identity.identityId());
            }
        }
    }

    private X509Certificate[] buildCertPath(@NonNull final X509Certificate cert) {
        List<X509Certificate> certs = new LinkedList<>();
        X509Certificate cur = cert;
        while (cur != null) {
            certs.add(cur);
            cur = getIssuerForCert(cur);
        }
        return certs.toArray(new X509Certificate[0]);
    }

    private X509Certificate getIssuerForCert(@NonNull final X509Certificate cert) {
        try {
            if (X509Util.isSelfSigned(cert)) {
                return null;
            }

            for (X509Cert cert2 : certificates.values()) {
                if (cert2.cert() == cert) {
                    continue;
                }

                if (X509Util.issues(cert2.cert(), cert)) {
                    return cert2.cert();
                }
            }
        } catch (CertificateEncodingException ex) {
            LOG.warn("invalid encoding of certificate {}", ex.getMessage());
        }
        return null;
    }

    @Override
    public void refresh() throws P11TokenException {
        P11SlotRefreshResult res = refresh0(); // CHECKSTYLE:SKIP

        mechanisms.clear();
        certificates.clear();
        identities.clear();

        List<Long> ignoreMechs = new ArrayList<>();

        for (Long mech : res.mechanisms()) {
            if (mechanismFilter.isMechanismPermitted(slotId, mech)) {
                mechanisms.add(mech);
            } else {
                ignoreMechs.add(mech);
            }
        }
        certificates.putAll(res.certificates());
        identities.putAll(res.identities());

        updateCaCertsOfIdentities();

        if (LOG.isInfoEnabled()) {
            StringBuilder sb = new StringBuilder();
            sb.append("initialized module ").append(moduleName).append(", slot ").append(slotId);

            sb.append("\nsupported mechanisms:\n");
            List<Long> sortedMechs = new ArrayList<>(mechanisms);
            Collections.sort(sortedMechs);
            for (Long mech : sortedMechs) {
                sb.append("\t").append(Pkcs11Functions.getMechanismDesc(mech)).append("\n");
            }

            sb.append("\nsupported by device but ignored mechanisms:\n");
            Collections.sort(ignoreMechs);
            for (Long mech : ignoreMechs) {
                sb.append("\t").append(Pkcs11Functions.getMechanismDesc(mech)).append("\n");
            }

            List<P11ObjectIdentifier> ids = getSortedObjectIds(certificates.keySet());
            sb.append(ids.size()).append(" certificates:\n");
            for (P11ObjectIdentifier objectId : ids) {
                X509Cert entity = certificates.get(objectId);
                sb.append("\t").append(objectId);
                sb.append(", subject='").append(entity.subject()).append("'\n");
            }

            ids = getSortedObjectIds(identities.keySet());
            sb.append(ids.size()).append(" identities:\n");
            for (P11ObjectIdentifier objectId : ids) {
                P11Identity identity = identities.get(objectId);
                sb.append("\t").append(objectId);
                if (identity.publicKey() != null) {
                    sb.append(", algo=").append(identity.publicKey().getAlgorithm());
                    if (identity.certificate() != null) {
                        String subject = X509Util.getRfc4519Name(
                                identity.certificate().getSubjectX500Principal());
                        sb.append(", subject='").append(subject).append("'");
                    }
                } else {
                    sb.append(", algo=<symmetric>");
                }
                sb.append("\n");
            }

            LOG.info(sb.toString());
        }
    }

    protected void addIdentity(final P11Identity identity) throws P11DuplicateEntityException {
        if (!slotId.equals(identity.identityId().slotId())) {
            throw new IllegalArgumentException("invalid identity");
        }

        P11ObjectIdentifier objectId = identity.identityId().objectId();
        if (hasIdentity(objectId)) {
            throw new P11DuplicateEntityException(slotId, objectId);
        }

        identities.put(objectId, identity);
        updateCaCertsOfIdentity(identity);
    }

    @Override
    public boolean hasIdentity(final P11ObjectIdentifier objectId) {
        return identities.containsKey(objectId);
    }

    @Override
    public Set<Long> mechanisms() {
        return Collections.unmodifiableSet(mechanisms);
    }

    @Override
    public boolean supportsMechanism(final long mechanism) {
        return mechanisms.contains(mechanism);
    }

    @Override
    public void assertMechanismSupported(final long mechanism)
            throws P11UnsupportedMechanismException {
        if (!mechanisms.contains(mechanism)) {
            throw new P11UnsupportedMechanismException(mechanism, slotId);
        }
    }

    @Override
    public Set<P11ObjectIdentifier> identityIdentifiers() {
        return Collections.unmodifiableSet(identities.keySet());
    }

    @Override
    public Set<P11ObjectIdentifier> certIdentifiers() {
        return Collections.unmodifiableSet(certificates.keySet());
    }

    @Override
    public String moduleName() {
        return moduleName;
    }

    @Override
    public P11SlotIdentifier slotId() {
        return slotId;
    }

    @Override
    public boolean isReadOnly() {
        return readOnly;
    }

    @Override
    public P11Identity getIdentity(final P11ObjectIdentifier objectId)
            throws P11UnknownEntityException {
        P11Identity ident = identities.get(objectId);
        if (ident == null) {
            throw new P11UnknownEntityException(slotId, objectId);
        }
        return ident;
    }

    @Override
    public P11ObjectIdentifier getObjectIdForId(final byte[] id) {
        for (P11ObjectIdentifier objectId : identities.keySet()) {
            if (objectId.matchesId(id)) {
                return objectId;
            }
        }

        for (P11ObjectIdentifier objectId : certificates.keySet()) {
            if (objectId.matchesId(id)) {
                return objectId;
            }
        }

        return null;
    }

    @Override
    public P11ObjectIdentifier getObjectIdForLabel(final String label) {
        for (P11ObjectIdentifier objectId : identities.keySet()) {
            if (objectId.label().equals(label)) {
                return objectId;
            }
        }

        for (P11ObjectIdentifier objectId : certificates.keySet()) {
            if (objectId.label().equals(label)) {
                return objectId;
            }
        }

        return null;
    }

    @Override
    public X509Certificate exportCert(final P11ObjectIdentifier objectId)
            throws P11TokenException, CertificateException {
        ParamUtil.requireNonNull("objectId", objectId);
        try {
            return getIdentity(objectId).certificate();
        } catch (P11UnknownEntityException ex) {
            // CHECKSTYLE:SKIP
        }

        X509Cert cert = certificates.get(objectId);
        if (cert == null) {
            throw new P11UnknownEntityException(slotId, objectId);
        }
        return cert.cert();
    }

    @Override
    public void removeCerts(final P11ObjectIdentifier objectId) throws P11TokenException {
        ParamUtil.requireNonNull("objectId", objectId);
        assertWritable("removeCerts");

        if (identities.containsKey(objectId)) {
            certificates.remove(objectId);
            identities.get(objectId).setCertificates(null);
        } else if (certificates.containsKey(objectId)) {
            certificates.remove(objectId);
        } else {
            throw new P11UnknownEntityException(slotId, objectId);
        }

        updateCaCertsOfIdentities();
        removeCerts0(objectId);
    }

    @Override
    public void removeIdentity(final P11ObjectIdentifier objectId) throws P11TokenException {
        ParamUtil.requireNonNull("objectId", objectId);
        assertWritable("removeIdentity");

        if (identities.containsKey(objectId)) {
            certificates.remove(objectId);
            identities.get(objectId).setCertificates(null);
            identities.remove(objectId);
            updateCaCertsOfIdentities();
        }

        removeIdentity0(objectId);
    }

    @Override
    public P11ObjectIdentifier addCert(final X509Certificate cert)
            throws P11TokenException, CertificateException {
        ParamUtil.requireNonNull("cert", cert);
        assertWritable("addCert");

        byte[] encodedCert = cert.getEncoded();
        for (P11ObjectIdentifier objectId : certificates.keySet()) {
            X509Cert tmpCert = certificates.get(objectId);
            if (Arrays.equals(encodedCert, tmpCert.encodedCert())) {
                return objectId;
            }
        }

        byte[] id = generateId();
        String cn = X509Util.getCommonName(cert.getSubjectX500Principal());
        String label = generateLabel(cn);
        P11ObjectIdentifier objectId = new P11ObjectIdentifier(id, label);
        addCert(objectId, cert);
        return objectId;
    }

    @Override
    public void addCert(final P11ObjectIdentifier objectId, final X509Certificate cert)
            throws P11TokenException, CertificateException {
        addCert0(objectId, cert);
        certificates.put(objectId, new X509Cert(cert));
        updateCaCertsOfIdentities();
        LOG.info("added certificate {}", objectId);
    }

    protected byte[] generateId() throws P11TokenException {
        byte[] id = new byte[8];

        while (true) {
            random.nextBytes(id);
            boolean duplicated = false;
            for (P11ObjectIdentifier objectId : identities.keySet()) {
                if (objectId.matchesId(id)) {
                    duplicated = true;
                    break;
                }
            }

            if (!duplicated) {
                for (P11ObjectIdentifier objectId : certificates.keySet()) {
                    if (objectId.matchesId(id)) {
                        duplicated = true;
                        break;
                    }
                }
            }

            if (!duplicated) {
                return id;
            }
        }
    }

    protected String generateLabel(final String label) throws P11TokenException {

        String tmpLabel = label;
        int idx = 0;
        while (true) {
            boolean duplicated = false;
            for (P11ObjectIdentifier objectId : identities.keySet()) {
                if (objectId.label().equals(label)) {
                    duplicated = true;
                    break;
                }
            }

            if (!duplicated) {
                for (P11ObjectIdentifier objectId : certificates.keySet()) {
                    if (objectId.label().equals(label)) {
                        duplicated = true;
                        break;
                    }
                }
            }

            if (!duplicated) {
                return tmpLabel;
            }

            idx++;
            tmpLabel = label + "-" + idx;
        }
    }

    @Override
    public P11ObjectIdentifier generateSecretKey(long keyType, int keysize, String label,
            P11NewKeyControl control)
            throws P11TokenException {
        ParamUtil.requireNonBlank("label", label);
        assertWritable("generateSecretKey");

        P11Identity identity = generateSecretKey0(keyType, keysize, label, control);
        addIdentity(identity);

        P11ObjectIdentifier objId = identity.identityId().objectId();
        LOG.info("generated secret key {}", objId);
        return objId;
    }

    @Override
    public P11ObjectIdentifier createSecretKey(long keyType, byte[] keyValue, String label,
            P11NewKeyControl control)
            throws P11TokenException {
        ParamUtil.requireNonBlank("label", label);
        assertWritable("createSecretKey");

        P11Identity identity = createSecretKey0(keyType, keyValue, label, control);
        addIdentity(identity);

        P11ObjectIdentifier objId = identity.identityId().objectId();
        LOG.info("created secret key {}", objId);
        return objId;
    }

    @Override
    public P11ObjectIdentifier generateRSAKeypair(final int keysize,
            final BigInteger publicExponent, final String label, P11NewKeyControl control)
            throws P11TokenException {
        ParamUtil.requireNonBlank("label", label);
        ParamUtil.requireMin("keysize", keysize, 1024);
        if (keysize % 1024 != 0) {
            throw new IllegalArgumentException("key size is not multiple of 1024: " + keysize);
        }
        assertWritable("generateRSAKeypair");
        assertMechanismSupported(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);

        BigInteger tmpPublicExponent = publicExponent;
        if (tmpPublicExponent == null) {
            tmpPublicExponent = BigInteger.valueOf(65537);
        }

        P11Identity identity = generateRSAKeypair0(keysize, tmpPublicExponent, label, control);
        addIdentity(identity);
        P11ObjectIdentifier objId = identity.identityId().objectId();
        LOG.info("generated RSA keypair {}", objId);
        return objId;
    }

    @Override
    public P11ObjectIdentifier generateDSAKeypair(final int plength, final int qlength,
            final String label, @NonNull P11NewKeyControl control) throws P11TokenException {
        ParamUtil.requireMin("plength", plength, 1024);
        if (plength % 1024 != 0) {
            throw new IllegalArgumentException("key size is not multiple of 1024: " + plength);
        }
        assertWritable("generateDSAKeypair");
        assertMechanismSupported(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN);

        DSAParameterSpec dsaParams = DSAParameterCache.getDSAParameterSpec(plength, qlength,
                random);
        P11Identity identity = generateDSAKeypair0(dsaParams.getP(), dsaParams.getQ(),
                dsaParams.getG(), label, control);
        addIdentity(identity);
        P11ObjectIdentifier objId = identity.identityId().objectId();
        LOG.info("generated DSA keypair {}", objId);
        return objId;
    }

    @Override
    // CHECKSTYLE:OFF
    public P11ObjectIdentifier generateDSAKeypair(final BigInteger p, final BigInteger q,
            final BigInteger g, final String label, P11NewKeyControl control)
            throws P11TokenException {
    // CHECKSTYLE:ON
        ParamUtil.requireNonBlank("label", label);
        ParamUtil.requireNonNull("p", p);
        ParamUtil.requireNonNull("q", q);
        ParamUtil.requireNonNull("g", g);
        assertWritable("generateDSAKeypair");
        assertMechanismSupported(PKCS11Constants.CKM_DSA_KEY_PAIR_GEN);

        P11Identity identity = generateDSAKeypair0(p, q, g, label, control);
        addIdentity(identity);
        P11ObjectIdentifier objId = identity.identityId().objectId();
        LOG.info("generated DSA keypair {}", objId);
        return objId;
    }

    @Override
    public P11ObjectIdentifier generateECKeypair(final String curveNameOrOid, final String label,
            P11NewKeyControl control)
            throws P11TokenException {
        ParamUtil.requireNonBlank("curveNameOrOid", curveNameOrOid);
        ParamUtil.requireNonBlank("label", label);
        assertWritable("generateECKeypair");
        assertMechanismSupported(PKCS11Constants.CKM_EC_KEY_PAIR_GEN);

        ASN1ObjectIdentifier curveId = AlgorithmUtil.getCurveOidForCurveNameOrOid(curveNameOrOid);
        if (curveId == null) {
            throw new IllegalArgumentException("unknown curve " + curveNameOrOid);
        }
        P11Identity identity = generateECKeypair0(curveId, label, control);
        addIdentity(identity);
        P11ObjectIdentifier objId = identity.identityId().objectId();
        LOG.info("generated EC keypair {}", objId);
        return objId;
    }

    @Override
    public void updateCertificate(final P11ObjectIdentifier objectId, final X509Certificate newCert)
            throws P11TokenException, CertificateException {
        ParamUtil.requireNonNull("objectId", objectId);
        ParamUtil.requireNonNull("newCert", newCert);
        assertWritable("updateCertificate");

        P11Identity identity = identities.get(objectId);
        if (identity == null) {
            throw new P11UnknownEntityException("could not find private key " + objectId);
        }

        java.security.PublicKey pk = identity.publicKey();
        java.security.PublicKey newPk = newCert.getPublicKey();
        if (!pk.equals(newPk)) {
            throw new P11TokenException("the given certificate is not for the key " + objectId);
        }

        updateCertificate0(objectId, newCert);
        identity.setCertificates(new X509Certificate[]{newCert});
        updateCaCertsOfIdentities();
        LOG.info("updated certificate {}", objectId);
    }

    @Override
    public void showDetails(final OutputStream stream, final boolean verbose)
            throws IOException, P11TokenException {
        ParamUtil.requireNonNull("stream", stream);

        List<P11ObjectIdentifier> sortedObjectIds = getSortedObjectIds(identities.keySet());
        int size = sortedObjectIds.size();

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < size; i++) {
            P11ObjectIdentifier objectId = sortedObjectIds.get(i);
            sb.append("\t").append(i + 1).append(". ").append(objectId.label());
            sb.append(" (").append("id: ").append(objectId.idHex()).append(")\n");
            P11Identity identity = identities.get(objectId);
            if (identity.publicKey() != null) {
                String algo = identity.publicKey().getAlgorithm();
                sb.append("\t\tAlgorithm: ").append(algo).append("\n");
                X509Certificate[] certs = identity.certificateChain();
                if (certs == null || certs.length == 0) {
                    sb.append("\t\tCertificate: NONE\n");
                } else {
                    for (int j = 0; j < certs.length; j++) {
                        formatString(j, verbose, sb, certs[j]);
                    }
                }
            } else {
                sb.append("\t\tSymmetric key\n");
            }
        }

        sortedObjectIds.clear();
        for (P11ObjectIdentifier objectId : certificates.keySet()) {
            if (!identities.containsKey(objectId)) {
                sortedObjectIds.add(objectId);
            }
        }
        Collections.sort(sortedObjectIds);

        if (!sortedObjectIds.isEmpty()) {
            Collections.sort(sortedObjectIds);
            size = sortedObjectIds.size();
            for (int i = 0; i < size; i++) {
                P11ObjectIdentifier objectId = sortedObjectIds.get(i);
                sb.append("\tCert-").append(i + 1).append(". ").append(objectId.label());
                sb.append(" (").append("id: ").append(objectId.label()).append(")\n");
                formatString(null, verbose, sb, certificates.get(objectId).cert());
            }
        }

        if (sb.length() > 0) {
            stream.write(sb.toString().getBytes());
        }
    }

    protected void assertWritable(final String operationName) throws P11PermissionException {
        if (readOnly) {
            throw new P11PermissionException("Operation " + operationName + " is not permitted");
        }
    }

    private static void formatString(final Integer index, final boolean verbose,
            final StringBuilder sb, final X509Certificate cert) {
        String subject = X509Util.getRfc4519Name(cert.getSubjectX500Principal());
        sb.append("\t\tCertificate");
        if (index != null) {
            sb.append("[").append(index).append("]");
        }
        sb.append(": ");

        if (!verbose) {
            sb.append(subject).append("\n");
            return;
        } else {
            sb.append("\n");
        }

        sb.append("\t\t\tSubject: ").append(subject).append("\n");

        String issuer = X509Util.getRfc4519Name(cert.getIssuerX500Principal());
        sb.append("\t\t\tIssuer: ").append(issuer).append("\n");
        sb.append("\t\t\tSerial: ").append(LogUtil.formatCsn(cert.getSerialNumber())).append("\n");
        sb.append("\t\t\tStart time: ").append(cert.getNotBefore()).append("\n");
        sb.append("\t\t\tEnd time: ").append(cert.getNotAfter()).append("\n");
        sb.append("\t\t\tSHA1 Sum: ");
        try {
            sb.append(HashAlgoType.SHA1.hexHash(cert.getEncoded()));
        } catch (CertificateEncodingException ex) {
            sb.append("ERROR");
        }
        sb.append("\n");
    }

    private List<P11ObjectIdentifier> getSortedObjectIds(Set<P11ObjectIdentifier> sets) {
        List<P11ObjectIdentifier> ids = new ArrayList<>(sets);
        Collections.sort(ids);
        return ids;
    }

}
