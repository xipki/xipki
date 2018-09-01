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

package org.xipki.ca.client.shell;

import java.io.File;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;

import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Reference;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.cmp.CMPObjectIdentifiers;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;
import org.bouncycastle.asn1.crmf.CertId;
import org.bouncycastle.asn1.crmf.CertRequest;
import org.bouncycastle.asn1.crmf.CertTemplateBuilder;
import org.bouncycastle.asn1.crmf.Controls;
import org.bouncycastle.asn1.crmf.OptionalValidity;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.asn1.x509.Time;
import org.xipki.ca.client.api.EnrollCertResult;
import org.xipki.ca.client.api.dto.EnrollCertRequest;
import org.xipki.ca.client.api.dto.EnrollCertRequestEntry;
import org.xipki.security.ExtensionExistence;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.security.SecurityFactory;
import org.xipki.security.util.X509Util;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.shell.completer.ExtensionNameCompleter;
import org.xipki.util.DateUtil;
import org.xipki.util.ReqRespDebug;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 * @since 4.0.0
 */

public abstract class UpdateAction extends ClientAction {

  @Reference
  protected SecurityFactory securityFactory;

  @Option(name = "--subject", aliases = "-s",
      description = "subject to be requested")
  private String subject;

  @Option(name = "--not-before", description = "notBefore, UTC time of format yyyyMMddHHmmss")
  private String notBeforeS;

  @Option(name = "--not-after", description = "notAfter, UTC time of format yyyyMMddHHmmss")
  private String notAfterS;

  @Option(name = "--ca", description = "CA name\n(required if more than one CA is configured)")
  @Completion(CaNameCompleter.class)
  private String caName;

  @Option(name = "--oldcert", description = "certificate files (exactly one of oldcert and\n"
      + " oldcert-serial must be specified")
  @Completion(FileCompleter.class)
  private String oldCertFile;

  @Option(name = "--oldcert-serial", description = "serial number of the old certificate")
  private String oldCSerialNumber;

  @Option(name = "--need-extension", multiValued = true,
      description = "type (name or OID) of extension that must be contained in the certificate")
  @Completion(ExtensionNameCompleter.class)
  private List<String> needExtensionTypes;

  @Option(name = "--want-extension", multiValued = true,
      description = "type (name or OID) of extension that should be contained in the"
          + " certificate if possible")
  @Completion(ExtensionNameCompleter.class)
  private List<String> wantExtensionTypes;

  protected abstract SubjectPublicKeyInfo getPublicKey() throws Exception;

  protected abstract EnrollCertRequestEntry buildEnrollCertRequestEntry(
      String id, String profile, CertRequest certRequest) throws Exception;

  protected EnrollCertResult enroll() throws Exception {
    Set<String> caNames = caClient.getCaNames();
    if (caName != null) {
      caName = caName.toLowerCase();
      if (!caNames.contains(caName)) {
        throw new IllegalCmdParamException("unknown CA " + caName);
      }
    } else {
      if (caNames.size() != 1) {
        throw new IllegalCmdParamException("please specify the CA");
      } else {
        caName = caNames.iterator().next();
      }
    }

    if (needExtensionTypes != null) {
      needExtensionTypes = EnrollAction.resolveExtensionTypes(needExtensionTypes);
    } else {
      needExtensionTypes = new LinkedList<>();
    }

    if (wantExtensionTypes != null) {
      wantExtensionTypes = EnrollAction.resolveExtensionTypes(wantExtensionTypes);
    } else {
      wantExtensionTypes = new LinkedList<>();
    }

    CertTemplateBuilder certTemplateBuilder = new CertTemplateBuilder();

    if (subject != null && !subject.isEmpty()) {
      certTemplateBuilder.setSubject(new X500Name(subject));
    }

    SubjectPublicKeyInfo publicKey = getPublicKey();
    if (publicKey != null) {
      certTemplateBuilder.setPublicKey(getPublicKey());
    }

    if (StringUtil.isNotBlank(notBeforeS) || StringUtil.isNotBlank(notAfterS)) {
      Time notBefore = StringUtil.isNotBlank(notBeforeS)
          ? new Time(DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS)) : null;
      Time notAfter = StringUtil.isNotBlank(notAfterS)
          ? new Time(DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS)) : null;
      OptionalValidity validity = new OptionalValidity(notBefore, notAfter);
      certTemplateBuilder.setValidity(validity);
    }

    List<Extension> extensions = new LinkedList<>();

    if (isNotEmpty(needExtensionTypes) || isNotEmpty(wantExtensionTypes)) {
      ExtensionExistence ee = new ExtensionExistence(
          EnrollAction.textToAsn1ObjectIdentifers(needExtensionTypes),
          EnrollAction.textToAsn1ObjectIdentifers(wantExtensionTypes));
      extensions.add(new Extension(ObjectIdentifiers.id_xipki_ext_cmpRequestExtensions, false,
                        ee.toASN1Primitive().getEncoded()));
    }

    if (isNotEmpty(extensions)) {
      Extensions asn1Extensions = new Extensions(extensions.toArray(new Extension[0]));
      certTemplateBuilder.setExtensions(asn1Extensions);
    }

    if (!(oldCertFile == null ^ oldCSerialNumber == null)) {
      throw new IllegalCmdParamException(
          "exactly one of oldcert and oldcert-serial must be specified");
    }

    CertId oldCertId;
    if (oldCertFile != null) {
      Certificate oldCert = X509Util.parseBcCert(new File(oldCertFile));
      oldCertId = new CertId(new GeneralName(oldCert.getIssuer()), oldCert.getSerialNumber());
    } else {
      X500Name issuer = caClient.getCaCertSubject(caName);
      oldCertId = new CertId(new GeneralName(issuer), toBigInt(oldCSerialNumber));
    }

    Controls controls = new Controls(
        new AttributeTypeAndValue(CMPObjectIdentifiers.regCtrl_oldCertID, oldCertId));

    CertRequest certReq = new CertRequest(1, certTemplateBuilder.build(), controls);

    EnrollCertRequestEntry reqEntry = buildEnrollCertRequestEntry("id-1", null, certReq);
    EnrollCertRequest request = new EnrollCertRequest(EnrollCertRequest.Type.KEY_UPDATE);
    request.addRequestEntry(reqEntry);

    ReqRespDebug debug = getReqRespDebug();
    EnrollCertResult result;
    try {
      result = caClient.enrollCerts(caName, request, debug);
    } finally {
      saveRequestResponse(debug);
    }

    return result;
  } // method enroll

}
