/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.io.IOException;
import java.io.Serializable;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.util.encoders.Base64;
import org.xipki.ca.common.CAMgmtException;
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.common.X509CertificateWithMetaInfo;
import org.xipki.security.common.CertRevocationInfo;
import org.xipki.security.common.IoCertUtil;
import org.xipki.security.common.ParamChecker;

/**
 * @author Lijun Liao
 */

public class CAEntry implements Serializable
{
    private String name;
    private CAStatus status;
    private List<String> crlUris;
    private List<String> deltaCrlUris;
    private List<String> ocspUris;
    private List<String> issuerLocations;
    private int maxValidity;
    private X509CertificateWithMetaInfo cert;
    private String signerType;
    private String signerConf;
    private String crlSignerName;
    private long nextSerial;
    private DuplicationMode duplicateKeyMode;
    private DuplicationMode duplicateSubjectMode;
    private ValidityMode validityMode = ValidityMode.STRICT;
    private Set<Permission> permissions;
    private int numCrls;
    private int expirationPeriod;
    private CertRevocationInfo revocationInfo;
    private int lastCRLInterval;
    private long lastCRLIntervalDate;
    private String subject;

    public CAEntry(String name, long initialSerial,
            String signerType, String signerConf, X509Certificate cert,
            List<String> ocspUris, List<String> crlUris, List<String> deltaCrlUris,
            List<String> issuerLocations, int numCrls,
            int expirationPeriod)
    throws CAMgmtException
    {
        init(name, initialSerial, signerType, signerConf, cert, ocspUris,
                crlUris, deltaCrlUris, issuerLocations, numCrls, expirationPeriod);
        this.serialVersion = SERIAL_VERSION;
    }

    private void init(String name, long initialSerial,
            String signerType, String signerConf, X509Certificate cert,
            List<String> ocspUris, List<String> crlUris, List<String> deltaCrlUris,
            List<String> issuerLocations, int numCrls,
            int expirationPeriod)
    throws CAMgmtException
    {
        ParamChecker.assertNotEmpty("name", name);
        ParamChecker.assertNotEmpty("signerType", signerType);
        ParamChecker.assertNotNull("cert", cert);

        if(initialSerial < 0)
        {
            throw new IllegalArgumentException("initialSerial is negative (" + initialSerial + " < 0)");
        }

        if(expirationPeriod < 0)
        {
            throw new IllegalArgumentException("expirationPeriod is negative (" + expirationPeriod + " < 0)");
        }
        this.expirationPeriod = expirationPeriod;

        if(numCrls < 0)
        {
            throw new IllegalArgumentException("numCrls could not be negative");
        }
        this.numCrls = numCrls;

        this.name = name;
        this.nextSerial = initialSerial;

        try
        {
            this.cert = new X509CertificateWithMetaInfo(cert, cert.getEncoded());
        } catch (CertificateEncodingException e)
        {
            throw new CAMgmtException("could not encode the CA certificate");
        }
        this.subject = IoCertUtil.canonicalizeName(cert.getSubjectX500Principal());

        this.signerType = signerType;
        this.signerConf = signerConf;

        this.ocspUris = (ocspUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(ocspUris));
        this.crlUris = (crlUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(crlUris));
        this.deltaCrlUris = (deltaCrlUris == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(deltaCrlUris));
        this.issuerLocations = (issuerLocations == null) ?
                null : Collections.unmodifiableList(new ArrayList<>(issuerLocations));
    }

    public String getName()
    {
        return name;
    }

    public long getNextSerial()
    {
        return nextSerial;
    }

    public void setNextSerial(long nextSerial)
    {
        this.nextSerial = nextSerial;
    }

    public List<String> getCrlUris()
    {
        return crlUris;
    }

    public String getCrlUrisAsString()
    {
        return toString(crlUris);
    }

    public List<String> getDeltaCrlUris()
    {
        return deltaCrlUris;
    }

    public String getDeltaCrlUrisAsString()
    {
        return toString(deltaCrlUris);
    }

    public List<String> getOcspUris()
    {
        return ocspUris;
    }

    public String getOcspUrisAsString()
    {
        return toString(ocspUris);
    }

    public int getMaxValidity()
    {
        return maxValidity;
    }

    public void setMaxValidity(int maxValidity)
    {
        this.maxValidity = maxValidity;
    }

    public X509CertificateWithMetaInfo getCertificate()
    {
        return cert;
    }

    public String getSignerConf()
    {
        return signerConf;
    }

    public String getCrlSignerName()
    {
        return crlSignerName;
    }

    public int getNumCrls()
    {
        return numCrls;
    }

    public void setCrlSignerName(String crlSignerName)
    {
        this.crlSignerName = crlSignerName;
    }

    public CAStatus getStatus()
    {
        return status;
    }
    public void setStatus(CAStatus status)
    {
        this.status = status;
    }

    public String getSignerType()
    {
        return signerType;
    }

    public List<String> getCaIssuerLocations()
    {
        return issuerLocations;
    }

    @Override
    public String toString()
    {
        return toString(false);
    }

    public String toString(boolean verbose)
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("next_serial: ").append(nextSerial).append('\n');
        sb.append("status: ").append(status.getStatus()).append('\n');
        sb.append("deltaCrl_uris: ").append(getDeltaCrlUrisAsString()).append('\n');
        sb.append("crl_uris: ").append(getCrlUrisAsString()).append('\n');
        sb.append("ocsp_uris: ").append(getOcspUrisAsString()).append('\n');
        sb.append("max_validity: ").append(maxValidity).append(" days\n");
        sb.append("expirationPeriod: ").append(expirationPeriod).append(" days\n");
        sb.append("signer_type: ").append(signerType).append('\n');
        sb.append("signer_conf: ").append(signerConf).append('\n');
        sb.append("cert: ").append("\n");
        sb.append("\tissuer: ").append(
                IoCertUtil.canonicalizeName(cert.getCert().getIssuerX500Principal())).append("\n");
        sb.append("\tserialNumber: ").append(cert.getCert().getSerialNumber()).append("\n");
        sb.append("\tsubject: ").append(subject).append("\n");
        sb.append("\tnotBefore: ").append(cert.getCert().getNotBefore()).append("\n");
        sb.append("\tnotAfter: ").append(cert.getCert().getNotAfter()).append("\n");
        if(verbose)
        {
            sb.append("\tEncoded: ").append(Base64.toBase64String(cert.getEncodedCert())).append("\n");
        }
        sb.append("crlsigner_name: ").append(crlSignerName).append('\n');
        sb.append("duplicateKey: ").append(duplicateKeyMode.getDescription()).append('\n');
        sb.append("duplicateSubject: ").append(duplicateSubjectMode.getDescription()).append('\n');
        sb.append("validityMode: ").append(validityMode).append('\n');
        sb.append("permissions: ").append(Permission.toString(permissions));
        sb.append("lastCRLInterval: ").append(lastCRLInterval).append('\n');
        sb.append("lastCRLIntervalDate: ").append(lastCRLIntervalDate).append('\n');

        return sb.toString();
    }

    private static String toString(Collection<String> tokens)
    {
        if(tokens == null || tokens.isEmpty())
        {
            return null;
        }

        StringBuilder sb = new StringBuilder();

        int size = tokens.size();
        int idx = 0;
        for(String token : tokens)
        {
            sb.append(token);
            if(idx++ < size - 1)
            {
                sb.append("\t");
            }
        }
        return sb.toString();
    }

    public DuplicationMode getDuplicateKeyMode()
    {
        return duplicateKeyMode;
    }

    public void setDuplicateKeyMode(DuplicationMode mode)
    {
        ParamChecker.assertNotNull("mode", mode);
        this.duplicateKeyMode = mode;
    }

    public DuplicationMode getDuplicateSubjectMode()
    {
        return duplicateSubjectMode;
    }

    public void setDuplicateSubjectMode(DuplicationMode mode)
    {
        ParamChecker.assertNotNull("mode", mode);
        this.duplicateSubjectMode = mode;
    }

    public ValidityMode getValidityMode()
    {
        return validityMode;
    }

    public void setValidityMode(ValidityMode mode)
    {
        ParamChecker.assertNotNull("mode", mode);
        this.validityMode = mode;
    }

    public Set<Permission> getPermissions()
    {
        return permissions;
    }

    public void setPermissions(Set<Permission> permissions)
    {
        this.permissions = (permissions == null) ? null : Collections.unmodifiableSet(permissions);
    }

    public CertRevocationInfo getRevocationInfo()
    {
        return revocationInfo;
    }

    public void setRevocationInfo(CertRevocationInfo revocationInfo)
    {
        this.revocationInfo = revocationInfo;
    }

    public int getExpirationPeriod()
    {
        return expirationPeriod;
    }

    public int getLastCRLInterval()
    {
        return lastCRLInterval;
    }

    public void setLastCRLInterval(int lastInterval)
    {
        this.lastCRLInterval = lastInterval;
    }

    public long getLastCRLIntervalDate()
    {
        return lastCRLIntervalDate;
    }

    public void setLastCRLIntervalDate(long lastIntervalDate)
    {
        this.lastCRLIntervalDate = lastIntervalDate;
    }

    public String getSubject()
    {
        return subject;
    }

    // ------------------------------------------------
    // Customized serialization
    // ------------------------------------------------
    private static final long serialVersionUID = 1L;

    private static final String SR_serialVersion = "serialVersion";
    private static final double SERIAL_VERSION = 1.0;

    private static final String SR_name = "name";
    private static final String SR_signerType = "signerType";
    private static final String SR_signerConf = "signerConf";
    private static final String SR_cert = "cert";
    private static final String SR_nextSerial = "nextSerial";
    private static final String SR_ocspUris = "ocspUris";
    private static final String SR_crlUris = "crlUris";
    private static final String SR_deltaCrlUris = "deltaCrlUris";
    private static final String SR_issuerLocations = "issuerLocations";
    private static final String SR_numCrls = "numCrls";
    private static final String SR_expirationPeriod = "expirationPeriod";
    private static final String SR_status = "status";
    private static final String SR_maxValidity = "maxValidity";
    private static final String SR_crlSignerName = "crlSignerName";
    private static final String SR_duplicateKeyMode = "duplicateKeyMode";
    private static final String SR_duplicateSubjectMode = "duplicateSubjectMode";
    private static final String SR_validityMode = "validityMode";
    private static final String SR_permissions = "permissions";
    private static final String SR_lastCRLInterval = "lastCRLInterval";
    private static final String SR_lastCRLIntervalDate = "lastCRLIntervalDate";

    private double serialVersion;

    private void writeObject(java.io.ObjectOutputStream out)
    throws IOException
    {
        final Map<String, Object> serialMap = new HashMap<String, Object>();

        serialMap.put(SR_serialVersion, serialVersion);
        serialMap.put(SR_name, name);
        serialMap.put(SR_signerType, signerType);
        serialMap.put(SR_signerConf, signerConf);
        serialMap.put(SR_nextSerial, nextSerial);
        serialMap.put(SR_ocspUris, ocspUris);
        serialMap.put(SR_crlUris, crlUris);
        serialMap.put(SR_deltaCrlUris, deltaCrlUris);
        serialMap.put(SR_issuerLocations, issuerLocations);
        serialMap.put(SR_numCrls, numCrls);
        serialMap.put(SR_expirationPeriod, expirationPeriod);
        serialMap.put(SR_status, status);
        serialMap.put(SR_maxValidity, maxValidity);
        serialMap.put(SR_crlSignerName, crlSignerName);
        serialMap.put(SR_duplicateKeyMode, duplicateKeyMode);
        serialMap.put(SR_duplicateSubjectMode, duplicateSubjectMode);
        serialMap.put(SR_validityMode, validityMode);
        serialMap.put(SR_permissions, permissions);
        serialMap.put(SR_lastCRLInterval, lastCRLInterval);
        serialMap.put(SR_lastCRLIntervalDate, lastCRLIntervalDate);
        SerializationUtil.writeCert(serialMap, SR_cert, cert == null ? null : cert.getCert());

        out.writeObject(serialMap);
    }

    @SuppressWarnings("unchecked")
    private void readObject(java.io.ObjectInputStream in)
    throws IOException, ClassNotFoundException
    {
        final Map<String, Object> serialMap = (Map<String, Object>) in.readObject();
        serialVersion = (double) serialMap.get(SR_serialVersion);

        String name = (String) serialMap.get(SR_name);
        long nextSerial = (long) serialMap.get(SR_nextSerial);
        String signerType = (String) serialMap.get(SR_signerType);
        String signerConf = (String) serialMap.get(SR_signerConf);
        X509Certificate cert = SerializationUtil.readCert(serialMap, SR_cert);
        List<String> ocspUris = (List<String>) serialMap.get(SR_ocspUris);
        List<String> crlUris = (List<String>) serialMap.get(SR_crlUris);
        List<String> deltaCrlUris = (List<String>) serialMap.get(SR_deltaCrlUris);
        List<String> issuerLocations = (List<String>) serialMap.get(SR_issuerLocations);
        int numCrls = (int) serialMap.get(SR_numCrls);
        int expirationPeriod = (int) serialMap.get(SR_expirationPeriod);

        try
        {
            init(name, nextSerial, signerType, signerConf, cert,
                    ocspUris, crlUris, deltaCrlUris, issuerLocations, numCrls, expirationPeriod);
        } catch (CAMgmtException e)
        {
            throw new IOException("CAMgmtException: " + e.getMessage(), e);
        }

        status = (CAStatus) serialMap.get(SR_status);
        maxValidity = (int) serialMap.get(SR_maxValidity);
        crlSignerName = (String) serialMap.get(SR_crlSignerName);
        duplicateKeyMode = (DuplicationMode) serialMap.get(SR_duplicateKeyMode);
        duplicateSubjectMode = (DuplicationMode) serialMap.get(SR_duplicateSubjectMode);
        validityMode = (ValidityMode) serialMap.get(SR_validityMode);
        permissions = (Set<Permission>) serialMap.get(SR_permissions);
        lastCRLInterval = (int) serialMap.get(SR_lastCRLInterval);
        lastCRLIntervalDate = (long) serialMap.get(SR_lastCRLIntervalDate);
    }
}
