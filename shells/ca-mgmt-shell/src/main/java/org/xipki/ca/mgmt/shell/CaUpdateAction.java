/*
 *
 * Copyright (c) 2013 - 2018 Lijun Liao
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.xipki.ca.mgmt.shell;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.xipki.ca.api.CaUris;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.mgmt.api.CaEntry;
import org.xipki.ca.mgmt.api.CaManager;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.api.CaStatus;
import org.xipki.ca.mgmt.api.ChangeCaEntry;
import org.xipki.ca.mgmt.api.ValidityMode;
import org.xipki.ca.mgmt.shell.completer.CaNameCompleter;
import org.xipki.ca.mgmt.shell.completer.CaStatusCompleter;
import org.xipki.ca.mgmt.shell.completer.PermissionCompleter;
import org.xipki.ca.mgmt.shell.completer.SignerNamePlusNullCompleter;
import org.xipki.ca.mgmt.shell.completer.SignerTypeCompleter;
import org.xipki.ca.mgmt.shell.completer.ValidityModeCompleter;
import org.xipki.password.PasswordResolver;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.completer.YesNoCompleter;
import org.xipki.util.CollectionUtil;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;
import org.xipki.util.ParamUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

@Command(scope = "ca", name = "ca-up", description = "update CA")
@Service
public class CaUpdateAction extends CaAction {

  @Option(name = "--name", aliases = "-n", required = true, description = "CA name")
  @Completion(CaNameCompleter.class)
  private String caName;

  @Option(name = "--sn-bitlen",
      description = "number of bits of the serial number, between 63 and 159")
  private Integer snBitLen;

  @Option(name = "--status", description = "CA status")
  @Completion(CaStatusCompleter.class)
  private String caStatus;

  @Option(name = "--ca-cert-uri", multiValued = true, description = "CA certificate URI")
  private List<String> caCertUris;

  @Option(name = "--ocsp-uri", multiValued = true, description = "OCSP URI or 'null'")
  private List<String> ocspUris;

  @Option(name = "--crl-uri", multiValued = true,
      description = "CRL distribution point URI or 'null'")
  private List<String> crlUris;

  @Option(name = "--deltacrl-uri", multiValued = true,
      description = "delta CRL distribution point URI or 'null'")
  private List<String> deltaCrlUris;

  @Option(name = "--permission", multiValued = true, description = "permission")
  @Completion(PermissionCompleter.class)
  private Set<String> permissions;

  @Option(name = "--max-validity", description = "maximal validity")
  private String maxValidity;

  @Option(name = "--expiration-period",
      description = "days before expiration time of CA to issue certificates")
  private Integer expirationPeriod;

  @Option(name = "--keep-expired-certs", description = "days to keep expired certificates")
  private Integer keepExpiredCertInDays;

  @Option(name = "--crl-signer", description = "CRL signer name or 'null'")
  @Completion(SignerNamePlusNullCompleter.class)
  private String crlSignerName;

  @Option(name = "--cmp-responder", description = "CMP responder name or 'null'")
  @Completion(SignerNamePlusNullCompleter.class)
  private String cmpResponderName;

  @Option(name = "--scep-responder", description = "SCEP responder name or 'null'")
  @Completion(SignerNamePlusNullCompleter.class)
  private String scepResponderName;

  @Option(name = "--cmp-control", description = "CMP control or 'null'")
  private String cmpControl;

  @Option(name = "--crl-control", description = "CRL control or 'null'")
  private String crlControl;

  @Option(name = "--scep-control", description = "SCEP control or 'null'")
  private String scepControl;

  @Option(name = "--num-crls", description = "number of CRLs to be kept in database")
  private Integer numCrls;

  @Option(name = "--cert", description = "CA certificate file")
  @Completion(FileCompleter.class)
  private String certFile;

  @Option(name = "--signer-type", description = "CA signer type")
  @Completion(SignerTypeCompleter.class)
  private String signerType;

  @Option(name = "--signer-conf", description = "CA signer configuration or 'null'")
  private String signerConf;

  @Option(name = "--duplicate-key", description = "whether duplicate key is permitted")
  @Completion(YesNoCompleter.class)
  private String duplicateKeyS;

  @Option(name = "--duplicate-subject", description = "whether duplicate subject is permitted")
  @Completion(YesNoCompleter.class)
  private String duplicateSubjectS;

  @Option(name = "--support-cmp", description = "whether the CMP protocol is supported")
  @Completion(YesNoCompleter.class)
  private String supportCmpS;

  @Option(name = "--support-rest", description = "whether the REST protocol is supported")
  @Completion(YesNoCompleter.class)
  private String supportRestS;

  @Option(name = "--support-scep", description = "whether the SCEP protocol is supported")
  @Completion(YesNoCompleter.class)
  private String supportScepS;

  @Option(name = "--save-req", description = "whether the request is saved")
  @Completion(YesNoCompleter.class)
  private String saveReqS;

  @Option(name = "--validity-mode", description = "mode of valditity")
  @Completion(ValidityModeCompleter.class)
  private String validityModeS;

  @Option(name = "--extra-control", description = "extra control")
  private String extraControl;

  @Reference
  private PasswordResolver passwordResolver;

  protected ChangeCaEntry getChangeCaEntry() throws Exception {
    ChangeCaEntry entry = new ChangeCaEntry(new NameId(null, caName));

    if (snBitLen != null) {
      ParamUtil.requireRange("sn-bitlen", snBitLen, 63, 159);
      entry.setSerialNoBitLen(snBitLen);
    }

    if (caStatus != null) {
      entry.setStatus(CaStatus.forName(caStatus));
    }

    if (expirationPeriod != null && expirationPeriod < 0) {
      throw new IllegalCmdParamException("invalid expirationPeriod: " + expirationPeriod);
    } else {
      entry.setExpirationPeriod(expirationPeriod);
    }

    if (keepExpiredCertInDays != null) {
      entry.setKeepExpiredCertInDays(keepExpiredCertInDays);
    }

    if (certFile != null) {
      entry.setEncodedCert(IoUtil.read(certFile));
    }

    if (signerConf != null) {
      String tmpSignerType = signerType;
      if (tmpSignerType == null) {
        CaEntry caEntry = caManager.getCa(caName);
        if (caEntry == null) {
          throw new IllegalCmdParamException("please specify the signerType");
        }
        tmpSignerType = caEntry.getSignerType();
      }

      signerConf = ShellUtil.canonicalizeSignerConf(tmpSignerType, signerConf,
          passwordResolver, securityFactory);
      entry.setSignerConf(signerConf);
    }

    if (duplicateKeyS != null) {
      entry.setDuplicateKeyPermitted(isEnabled(duplicateKeyS, true, "duplicate-key"));
    }

    if (duplicateSubjectS != null) {
      entry.setDuplicateSubjectPermitted(isEnabled(duplicateSubjectS, true, "duplicate-subject"));
    }

    if (supportCmpS != null) {
      entry.setSupportCmp(isEnabled(supportCmpS, false, "support-cmp"));
    }

    if (supportRestS != null) {
      entry.setSupportRest(isEnabled(supportRestS, false, "support-rest"));
    }

    if (supportScepS != null) {
      entry.setSupportScep(isEnabled(supportScepS, false, "support-scep"));
    }

    if (saveReqS != null) {
      entry.setSaveRequest(isEnabled(saveReqS, true, "save-req"));
    }

    if (CollectionUtil.isNonEmpty(permissions)) {
      int intPermission = ShellUtil.getPermission(permissions);
      entry.setPermission(intPermission);
    }

    CaUris caUris = new CaUris(getUris(caCertUris), getUris(ocspUris), getUris(crlUris),
        getUris(deltaCrlUris));
    entry.setCaUris(caUris);

    if (validityModeS != null) {
      ValidityMode validityMode = ValidityMode.forName(validityModeS);
      entry.setValidityMode(validityMode);
    }

    if (maxValidity != null) {
      entry.setMaxValidity(CertValidity.getInstance(maxValidity));
    }

    if (cmpControl != null) {
      entry.setCmpControl(cmpControl);
    }

    if (crlControl != null) {
      entry.setCrlControl(crlControl);
    }

    if (scepControl != null) {
      entry.setScepControl(scepControl);
    }

    if (cmpResponderName != null) {
      entry.setCmpResponderName(cmpResponderName);
    }

    if (scepResponderName != null) {
      entry.setScepResponderName(scepResponderName);
    }

    if (crlSignerName != null) {
      entry.setCrlSignerName(crlSignerName);
    }

    if (extraControl != null) {
      entry.setExtraControl(new ConfPairs(extraControl).unmodifiable());
    }

    if (numCrls != null) {
      entry.setNumCrls(numCrls);
    }

    return entry;
  } // method getChangeCaEntry

  @Override
  protected Object execute0() throws Exception {
    String msg = "CA " + caName;
    try {
      caManager.changeCa(getChangeCaEntry());
      println("updated " + msg);
      return null;
    } catch (CaMgmtException ex) {
      throw new CmdFailure("could not update " + msg + ", error: " + ex.getMessage(), ex);
    }
  }

  private static List<String> getUris(List<String> uris) {
    if (uris == null) {
      return null;
    }

    boolean clearUris = false;
    for (String uri : uris) {
      if (CaManager.NULL.equalsIgnoreCase(uri)) {
        clearUris = true;
        break;
      }
    }

    return clearUris ? Collections.emptyList() : new ArrayList<>(uris);
  }

}
