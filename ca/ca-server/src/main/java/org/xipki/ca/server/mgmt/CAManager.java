/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.server.mgmt;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;

import org.xipki.ca.api.CAMgmtException;
import org.xipki.ca.api.CAStatus;
import org.xipki.ca.cmp.server.CmpControl;
import org.xipki.ca.server.X509CA;
import org.xipki.ca.server.X509CACmpResponder;
import org.xipki.security.common.EnvironmentParameterResolver;

public interface CAManager
{
    public static final String NULL = "NULL";

    boolean unlockCA();

    void publishRootCA(String caname)
    throws CAMgmtException;

    boolean republishCertificates(String caname, String publisherName)
    throws CAMgmtException;

    void removeCA(String caname)
    throws CAMgmtException;

    boolean restartCaSystem();

    EnvironmentParameterResolver getEnvParameterResolver();

    X509CA getX509CA(String caname);

    X509CACmpResponder getX509CACmpResponder(String caname);

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

    Set<String> getCANames();

    void addCA(CAEntry newCaDbEntry)
    throws CAMgmtException;

    CAEntry getCA(String caName);

    void changeCA(String name, CAStatus status, Long nextSerial,
            X509Certificate cert,
            Set<String> crl_uris, Set<String> ocsp_uris,
            Integer max_validity, String signer_type, String signer_conf,
            String crlsigner_name, Boolean allow_duplicate_key,
            Boolean allow_duplicate_subject, Set<Permission> permissions,
            Integer numCrls)
    throws CAMgmtException;

    void setCANextSerial(String caName, long nextSerial)
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
            Integer period, Integer overlap, Boolean includeCerts)
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

    void changeCmpControl(Boolean requireConfirmCert, Integer messageTimeBias,
            Integer confirmWaitTime, Boolean sendCaCert)
    throws CAMgmtException;

    void addEnvParam(String name, String value)
    throws CAMgmtException;

    void removeEnvParam(String envParamName)
    throws CAMgmtException;

    void changeEnvParam(String name, String value)
    throws CAMgmtException;
}
