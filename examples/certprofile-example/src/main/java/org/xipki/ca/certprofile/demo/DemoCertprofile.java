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

package org.xipki.ca.certprofile.demo;

import java.util.Date;
import java.util.List;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.w3c.dom.Element;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionControl;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.certprofile.xml.XmlCertprofile;
import org.xipki.common.ConfPairs;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.XmlUtil;

/**
 * This class adds two extensions to the certificate.
 * <ol>
 *   <li>add the extraControl of CA</li>
 *   <li>add the text defined in the XML block, like
 *   <pre>
 *   &lt;sequence xmlns="urn:extra"&gt;
 *     &lt;text&gt;aaa&lt;/text&gt;
 *     &lt;text&gt;bbb&lt;/text&gt;
 *   &lt;/sequence&gt;
 *   </pre>
 *   </li>
 * </ol>
 * @author Lijun Liao
 * @since 3.0.1
 */

public class DemoCertprofile extends XmlCertprofile {

  public static final ASN1ObjectIdentifier id_demo_ca_extra_control =
      new ASN1ObjectIdentifier("1.2.3.4.1");

  public static final ASN1ObjectIdentifier id_demo_other_namespace =
      new ASN1ObjectIdentifier("1.2.3.4.2");

  private boolean addCaExtraControl;

  private boolean addSequence;

  private ASN1Sequence sequence;

  @Override
  protected void extraReset() {
    addCaExtraControl = false;
    addSequence = false;
    sequence = null;
  }

  @Override
  protected boolean initExtraExtension(ASN1ObjectIdentifier extnId, ExtensionControl extnControl,
      Object extnValue) throws CertprofileException {
    if (id_demo_ca_extra_control.equals(extnId)) {
      this.addCaExtraControl = true;
      return true;
    } else if (id_demo_other_namespace.equals(extnId)) {
      if (!(extnValue instanceof Element)) {
        throw new CertprofileException("extnValue is not an org.w3c.dom.Element");
      }
      Element el = (Element) extnValue;
      String ns = el.getNamespaceURI();
      String ln = el.getLocalName();
      if (!(ns.equals("urn:extra") && ln.equals("sequence"))) {
        throw new CertprofileException("element is not of {urn:extra}:sequence");
      }

      List<Element> textElements = XmlUtil.getElementChilden(el, ns, "text");
      if (CollectionUtil.isEmpty(textElements)) {
        throw new CertprofileException("no text element is defined");
      }

      int size = textElements.size();
      DERUTF8String[] texts = new DERUTF8String[size];
      for (int i = 0; i < size; i++) {
        String text = XmlUtil.getNodeValue(textElements.get(i));
        texts[i] = new DERUTF8String(text);
      }

      this.sequence = new DERSequence(texts);

      this.addSequence = true;
      return true;
    } else {
      return false;
    }
  }

  @Override
  public ExtensionValues getExtraExtensions(
      Map<ASN1ObjectIdentifier, ExtensionControl> extensionOccurences,
      X500Name requestedSubject, X500Name grantedSubject, Extensions requestedExtensions,
      Date notBefore, Date notAfter, PublicCaInfo caInfo)
      throws CertprofileException, BadCertTemplateException {
    ExtensionValues extnValues = new ExtensionValues();

    if (addCaExtraControl) {
      ASN1ObjectIdentifier type = id_demo_ca_extra_control;
      ExtensionControl extnControl = extensionOccurences.get(type);
      if (extnControl != null) {
        ConfPairs caExtraControl = caInfo.getExtraControl();
        String name = "name-a";
        String value = null;
        if (caExtraControl != null) {
          value = caExtraControl.value(name);
        }

        if (value == null) {
          value = "UNDEF";
        }

        ExtensionValue extnValue = new ExtensionValue(extnControl.isCritical(),
            new DERUTF8String(name + ": " + value));
        extnValues.addExtension(type, extnValue);
      }
    }

    if (addSequence) {
      ASN1ObjectIdentifier type = id_demo_other_namespace;
      ExtensionControl extnControl = extensionOccurences.get(type);
      if (extnControl != null) {
        if (sequence == null) {
          throw new IllegalStateException("CertProfile is not initialized");
        }

        ExtensionValue extnValue = new ExtensionValue(extnControl.isCritical(), sequence);
        extnValues.addExtension(type, extnValue);
      }
    }

    return extnValues.size() == 0 ? null : extnValues;
  } // method getExtensions

}
