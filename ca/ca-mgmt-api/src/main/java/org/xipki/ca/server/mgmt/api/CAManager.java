/*
 * Copyright (c) 2014 Lijun Liao
 *
 * TO-BE-DEFINE
 *
 */

package org.xipki.ca.server.mgmt.api;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Set;

import org.xipki.ca.common.CAMgmtException;
import org.xipki.ca.common.CAStatus;
import org.xipki.ca.common.CASystemStatus;
import org.xipki.ca.common.CmpControl;
import org.xipki.common.CRLReason;
import org.xipki.common.CertRevocationInfo;

/**
 * @author Lijun Liao
 */

public interface CAManager
{
    public static final String NULL = "NULL";

    CASystemStatus getCASystemStatus();

    boolean unlockCA();

    void publishRootCA(String caName, String certprofile)
    throws CAMgmtException;

    boolean republishCertificates(String caName, List<String> publisherNames)
    throws CAMgmtException;

    boolean clearPublishQueue(String caName, List<String> publisherNames)
    throws CAMgmtException;

    void removeCA(String caName)
    throws CAMgmtException;

    boolean restartCaSystem();

    void addCaAlias(String aliasName, String caName)
    throws CAMgmtException;

    void removeCaAlias(String aliasName)
    throws CAMgmtException;

    String getAliasName(String caName);
    String getCaName(String aliasName);

    Set<String> getCaAliasNames();

    Set<String> getCertProfileNames();

    Set<String> getPublisherNames();

    Set<String> getCmpRequestorNames();

    Set<String> getCrlSignerNames();

    Set<String> getCaNames();

    void addCA(CAEntry newCaDbEntry)
    throws CAMgmtException;

    CAEntry getCA(String caName);

    void changeCA(String name, CAStatus status,
            X509Certificate cert,
            Set<String> crl_uris, Set<String> delta_crl_uris, Set<String> ocsp_uris,
            Integer max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            Integer numCrls, Integer expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException;

    void removeCertProfileFromCA(String profileName, String caName)
    throws CAMgmtException;

    void addCertProfileToCA(String profileName, String caName)
    throws CAMgmtException;

    void removePublisherFromCA(String publisherName, String caName)
    throws CAMgmtException;

    void addPublisherToCA(String publisherName, String caName)
    throws CAMgmtException;

    Set<String> getCertProfilesForCA(String caName);

    Set<CAHasRequestorEntry> getCmpRequestorsForCA(String caName);

    CmpRequestorEntry getCmpRequestor(String name);

    void addCmpRequestor(CmpRequestorEntry dbEntry)
    throws CAMgmtException;

    void removeCmpRequestor(String requestorName)
    throws CAMgmtException;

    void changeCmpRequestor(String name, String cert)
    throws CAMgmtException;

    void removeCmpRequestorFromCA(String requestorName, String caName)
    throws CAMgmtException;

    void addCmpRequestorToCA(CAHasRequestorEntry requestor, String caName)
    throws CAMgmtException;

    CertProfileEntry getCertProfile(String profileName);

    void removeCertProfile(String profileName)
    throws CAMgmtException;

    void changeCertProfile(String name, String type, String conf)
    throws CAMgmtException;

    void addCertProfile(CertProfileEntry dbEntry)
    throws CAMgmtException;

    void setCmpResponder(CmpResponderEntry dbEntry)
    throws CAMgmtException;

    void removeCmpResponder()
    throws CAMgmtException;

    void changeCmpResponder(String type, String conf, String cert)
    throws CAMgmtException;

    CmpResponderEntry getCmpResponder();

    void addCrlSigner(CrlSignerEntry dbEntry)
    throws CAMgmtException;

    void removeCrlSigner(String crlSignerName)
    throws CAMgmtException;

    void changeCrlSigner(String name, String signer_type, String signer_conf, String signer_cert,
            String crlControl)
    throws CAMgmtException;

    CrlSignerEntry getCrlSigner(String name);

    void setCrlSignerInCA(String crlSignerName, String caName)
    throws CAMgmtException;

    void addPublisher(PublisherEntry dbEntry)
    throws CAMgmtException;

    List<PublisherEntry> getPublishersForCA(String caName);

    PublisherEntry getPublisher(String publisherName);

    void removePublisher(String publisherName)
    throws CAMgmtException;

    void changePublisher(String name, String type, String conf)
    throws CAMgmtException;

    CmpControl getCmpControl();

    void setCmpControl(CmpControl dbEntry)
    throws CAMgmtException;

    void removeCmpControl()
    throws CAMgmtException;

    void changeCmpControl(Boolean requireConfirmCert,
            Boolean requireMessageTime, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert, Boolean sendResponderCert)
    throws CAMgmtException;

    Set<String> getEnvParamNames();

    String getEnvParam(String name);

    void addEnvParam(String name, String value)
    throws CAMgmtException;

    void removeEnvParam(String envParamName)
    throws CAMgmtException;

    void changeEnvParam(String name, String value)
    throws CAMgmtException;

    void revokeCa(String caName, CertRevocationInfo revocationInfo)
    throws CAMgmtException;

    void unrevokeCa(String caName)
    throws CAMgmtException;

    boolean revokeCertificate(String caName, BigInteger serialNumber, CRLReason reason, Date invalidityTime)
    throws CAMgmtException;

    boolean unrevokeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException;

    boolean removeCertificate(String caName, BigInteger serialNumber)
    throws CAMgmtException;

    X509Certificate generateCertificate(String caName, String profileName, String user, byte[] encodedPkcs10Request)
    throws CAMgmtException;

    public X509Certificate generateSelfSignedCA(
            String name, String certprofileName, String subject,
            CAStatus status, long nextSerial,
            List<String> crl_uris, List<String> delta_crl_uris, List<String> ocsp_uris,
            int max_validity, String signer_type, String signer_conf,
            String crlsigner_name, DuplicationMode duplicate_key,
            DuplicationMode duplicate_subject, Set<Permission> permissions,
            int numCrls, int expirationPeriod, ValidityMode validityMode)
    throws CAMgmtException;
}
