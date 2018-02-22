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

package org.xipki.ca.server.mgmt.api.x509;

import java.security.cert.X509Certificate;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.ca.api.NameId;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.CompareUtil;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.SignerConf;
import org.xipki.security.util.X509Util;

/**
 * TODO.
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ScepEntry {

  private static final Logger LOG = LoggerFactory.getLogger(ScepEntry.class);

  private final String name;

  private final NameId caIdent;

  private final boolean active;

  private final Set<String> certProfiles;

  private final String control;

  private final String responderType;

  private final String base64Cert;

  private String responderConf;

  private X509Certificate certificate;

  private boolean certFaulty;

  private boolean confFaulty;

  public ScepEntry(String name, NameId caIdent, boolean active, String responderType,
      String responderConf, String base64Cert, Set<String> certProfiles, String control)
      throws InvalidConfException {
    this.name = ParamUtil.requireNonBlank("name", name).toLowerCase();
    this.caIdent = ParamUtil.requireNonNull("caIdent", caIdent);
    this.active = active;
    this.responderType = ParamUtil.requireNonBlank("responderType", responderType);
    this.certProfiles = CollectionUtil.unmodifiableSet(
        CollectionUtil.toLowerCaseSet(certProfiles));
    this.base64Cert = base64Cert;
    this.responderConf = responderConf;
    this.control = control;

    if (this.base64Cert != null) {
      try {
        this.certificate = X509Util.parseBase64EncodedCert(base64Cert);
      } catch (Throwable th) {
        LOG.debug("could not parse the certificate of SCEP responder for CA '"
            + caIdent + "'");
        certFaulty = true;
      }
    }
  }

  public String name() {
    return name;
  }

  public boolean active() {
    return active;
  }

  public X509Certificate certificate() {
    return certificate;
  }

  public String base64Cert() {
    return base64Cert;
  }

  public Set<String> certProfiles() {
    return certProfiles;
  }

  public String control() {
    return control;
  }

  public String responderType() {
    return responderType;
  }

  public void setResponderConf(String conf) {
    this.responderConf = conf;
  }

  public String responderConf() {
    return responderConf;
  }

  public boolean faulty() {
    return certFaulty || confFaulty;
  }

  public void setConfFaulty(boolean faulty) {
    this.confFaulty = faulty;
  }

  public NameId caIdent() {
    return caIdent;
  }

  public void setCertificate(X509Certificate certificate) {
    if (base64Cert != null) {
      throw new IllegalStateException("certificate is already by specified by base64Cert");
    }
    this.certificate = certificate;
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    return toString(verbose, true);
  }

  public String toString(boolean verbose, boolean ignoreSensitiveInfo) {
    return StringUtil.concatObjects("ca: ", caIdent, "\nactive: ", active,
        "\nfaulty: ", faulty(), "\nresponderType: ", responderType,
        "\nresponderConf: ", (responderConf == null ? "null"
            : SignerConf.toString(responderConf, verbose, ignoreSensitiveInfo)),
        "\ncontrol: ", control,
        "\ncert\n", InternUtil.formatCert(certificate, verbose));
  } // method toString

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof ScepEntry)) {
      return false;
    }

    ScepEntry objB = (ScepEntry) obj;
    if (!caIdent.equals(objB.caIdent)) {
      return false;
    }

    if (active != objB.active) {
      return false;
    }

    if (!responderType.equals(objB.responderType)) {
      return false;
    }

    if (!CompareUtil.equalsObject(responderConf, objB.responderConf)) {
      return false;
    }

    if (!CompareUtil.equalsObject(control, objB.control)) {
      return false;
    }

    if (!CompareUtil.equalsObject(base64Cert, objB.base64Cert)) {
      return false;
    }

    return false;
  }

  @Override
  public int hashCode() {
    return caIdent.hashCode();
  }

}
