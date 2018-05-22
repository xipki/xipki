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

package org.xipki.ca.server.mgmt.shell;

import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.xipki.ca.api.NameId;
import org.xipki.ca.api.profile.CertValidity;
import org.xipki.ca.server.mgmt.api.CaEntry;
import org.xipki.ca.server.mgmt.api.CaStatus;
import org.xipki.ca.server.mgmt.api.CaUris;
import org.xipki.ca.server.mgmt.api.CmpControl;
import org.xipki.ca.server.mgmt.api.CrlControl;
import org.xipki.ca.server.mgmt.api.ValidityMode;
import org.xipki.ca.server.mgmt.shell.completer.CaStatusCompleter;
import org.xipki.ca.server.mgmt.shell.completer.PermissionCompleter;
import org.xipki.ca.server.mgmt.shell.completer.SignerNameCompleter;
import org.xipki.ca.server.mgmt.shell.completer.SignerTypeCompleter;
import org.xipki.ca.server.mgmt.shell.completer.ValidityModeCompleter;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.console.karaf.IllegalCmdParamException;
import org.xipki.console.karaf.completer.YesNoCompleter;
import org.xipki.password.PasswordResolver;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public abstract class CaAddOrGenAction extends CaAction {

  @Option(name = "--name", aliases = "-n", required = true, description = "CA name\n(required)")
  private String caName;

  @Option(name = "--status", description = "CA status")
  @Completion(CaStatusCompleter.class)
  private String caStatus = "active";

  @Option(name = "--rest-status", description = "REST API status")
  @Completion(CaStatusCompleter.class)
  private String restStatus = "inactive";

  @Option(name = "--ca-cert-uri", multiValued = true,
      description = "CA certificate URI\n(multi-valued)")
  private List<String> caCertUris;

  @Option(name = "--ocsp-uri", multiValued = true, description = "OCSP URI\n(multi-valued)")
  private List<String> ocspUris;

  @Option(name = "--crl-uri", multiValued = true,
      description = "CRL distribution point\n(multi-valued)")
  private List<String> crlUris;

  @Option(name = "--deltacrl-uri", multiValued = true,
      description = "CRL distribution point\n(multi-valued)")
  private List<String> deltaCrlUris;

  @Option(name = "--permission", required = true, multiValued = true,
      description = "permission\n(required, multi-valued)")
  @Completion(PermissionCompleter.class)
  private Set<String> permissions;

  @Option(name = "--sn-bitlen",
      description = "number of bits of the serial number, between 63 and 159")
  private int snBitLen = 127;

  @Option(name = "--next-crl-no", required = true,
      description = "CRL number for the next CRL\n(required)")
  private Long nextCrlNumber;

  @Option(name = "--max-validity", required = true, description = "maximal validity\n (required)")
  private String maxValidity;

  @Option(name = "--keep-expired-certs", description = "days to keep expired certificates")
  private Integer keepExpiredCertInDays = -1;

  @Option(name = "--crl-signer", description = "CRL signer name")
  @Completion(SignerNameCompleter.class)
  private String crlSignerName;

  @Option(name = "--responder", description = "Responder name")
  @Completion(SignerNameCompleter.class)
  private String responderName;

  @Option(name = "--cmp-control", description = "CMP control")
  private String cmpControl;

  @Option(name = "--crl-control", description = "CRL control")
  private String crlControl;

  @Option(name = "--num-crls", description = "number of CRLs to be kept in database")
  private Integer numCrls = 30;

  @Option(name = "--expiration-period",
      description = "days before expiration time of CA to issue certificates")
  private Integer expirationPeriod = 365;

  @Option(name = "--signer-type", required = true, description = "CA signer type\n(required)")
  @Completion(SignerTypeCompleter.class)
  private String signerType;

  @Option(name = "--signer-conf", required = true, description = "CA signer configuration")
  private String signerConf;

  @Option(name = "--duplicate-key", description = "whether duplicate key is permitted")
  @Completion(YesNoCompleter.class)
  private String duplicateKeyS = "yes";

  @Option(name = "--duplicate-subject", description = "whether duplicate subject is permitted")
  @Completion(YesNoCompleter.class)
  private String duplicateSubjectS = "yes";

  @Option(name = "--support-rest", description = "whether the REST API is supported")
  @Completion(YesNoCompleter.class)
  private String supportRestS = "no";

  @Option(name = "--save-req", description = "whether the request is saved")
  @Completion(YesNoCompleter.class)
  private String saveReqS = "no";

  @Option(name = "--validity-mode", description = "mode of valditity")
  @Completion(ValidityModeCompleter.class)
  private String validityModeS = "STRICT";

  @Option(name = "--extra-control", description = "extra control")
  private String extraControl;

  @Reference
  private PasswordResolver passwordResolver;

  protected CaEntry getCaEntry() throws Exception {
    ParamUtil.requireRange("sn-bitlen", snBitLen, 63, 159);

    if (nextCrlNumber < 1) {
      throw new IllegalCmdParamException("invalid CRL number: " + nextCrlNumber);
    }

    if (numCrls < 0) {
      throw new IllegalCmdParamException("invalid numCrls: " + numCrls);
    }

    if (expirationPeriod < 0) {
      throw new IllegalCmdParamException("invalid expirationPeriod: " + expirationPeriod);
    }

    if ("PKCS12".equalsIgnoreCase(signerType) || "JKS".equalsIgnoreCase(signerType)) {
      signerConf = ShellUtil.canonicalizeSignerConf(signerType, signerConf, passwordResolver,
          securityFactory);
    }

    CaUris caUris = new CaUris(caCertUris, ocspUris, crlUris, deltaCrlUris);
    CaEntry entry = new CaEntry(new NameId(null, caName), snBitLen, nextCrlNumber,
        signerType, signerConf, caUris, numCrls.intValue(), expirationPeriod.intValue());

    entry.setKeepExpiredCertInDays(keepExpiredCertInDays.intValue());

    boolean duplicateKeyPermitted = isEnabled(duplicateKeyS, true, "duplicate-key");
    entry.setDuplicateKeyPermitted(duplicateKeyPermitted);

    boolean duplicateSubjectPermitted = isEnabled(duplicateSubjectS, true, "duplicate-subject");
    entry.setDuplicateSubjectPermitted(duplicateSubjectPermitted);

    entry.setSupportRest(isEnabled(supportRestS, false, "support-scep"));
    entry.setSaveRequest(isEnabled(saveReqS, false, "save-req"));

    ValidityMode validityMode = ValidityMode.forName(validityModeS);
    entry.setValidityMode(validityMode);

    entry.setStatus(CaStatus.forName(caStatus));

    if (cmpControl != null) {
      entry.setCmpControl(new CmpControl(cmpControl));
    }

    if (crlControl != null) {
      entry.setCrlControl(new CrlControl(crlControl));
    }

    if (responderName != null) {
      entry.setResponderName(responderName);
    }

    if (crlSignerName != null) {
      entry.setCrlSignerName(crlSignerName);
    }

    CertValidity tmpMaxValidity = CertValidity.getInstance(maxValidity);
    entry.setMaxValidity(tmpMaxValidity);

    entry.setKeepExpiredCertInDays(keepExpiredCertInDays);

    int intPermission = ShellUtil.getPermission(permissions);
    entry.setPermission(intPermission);

    if (extraControl != null) {
      extraControl = extraControl.trim();
    }
    if (StringUtil.isNotBlank(extraControl)) {
      entry.setExtraControl(new ConfPairs(extraControl).unmodifiable());
    }
    return entry;
  } // method getCaEntry

}
