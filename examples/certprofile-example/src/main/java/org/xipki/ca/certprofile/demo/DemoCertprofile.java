/*
 *
 * Copyright (c) 2013 - 2019 Lijun Liao
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
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.api.BadCertTemplateException;
import org.xipki.ca.api.PublicCaInfo;
import org.xipki.ca.api.profile.CertprofileException;
import org.xipki.ca.api.profile.ExtensionValue;
import org.xipki.ca.api.profile.ExtensionValues;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType;
import org.xipki.util.ConfPairs;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;

/**
 * TODO.
 * @author Lijun Liao
 */

public class DemoCertprofile extends XijsonCertprofile {

  public static class ExtnDemoWithConf {
    private List<String> texts;

    public List<String> getTexts() {
      return texts;
    }

    public void setTexts(List<String> texts) {
      this.texts = texts;
    }

  }

  public static final ASN1ObjectIdentifier id_demo_without_conf =
      new ASN1ObjectIdentifier("1.2.3.4.1");

  public static final ASN1ObjectIdentifier id_demo_with_conf =
      new ASN1ObjectIdentifier("1.2.3.4.2");

  private boolean addExtraWithoutConf;

  private boolean addExtraWithConf;

  private ASN1Sequence sequence;

  @Override
  protected void extraReset() {
    addExtraWithoutConf = false;
    addExtraWithConf = false;
    sequence = null;
  }

  @Override
  protected boolean initExtraExtension(ExtensionType extn) throws CertprofileException {
    ASN1ObjectIdentifier extnId = extn.getType().toXiOid();
    if (id_demo_without_conf.equals(extnId)) {
      this.addExtraWithoutConf = true;
      return true;
    } else if (id_demo_with_conf.equals(extnId)) {
      Object customObj = extn.getCustom();
      if (customObj == null) {
        throw new CertprofileException("ExtensionType.custom is not specified");
      }

      if (!(customObj instanceof JSONObject)) {
        throw new CertprofileException("ExtensionType.custom is not configured correctly");
      }

      // we need to first serialize the configuration
      byte[] serializedConf = JSON.toJSONBytes(customObj);
      ExtnDemoWithConf conf = JSON.parseObject(serializedConf, ExtnDemoWithConf.class);

      List<String> list = conf.getTexts();
      DERUTF8String[] texts = new DERUTF8String[list.size()];
      for (int i = 0; i < list.size(); i++) {
        texts[i] = new DERUTF8String(list.get(i));
      }

      this.sequence = new DERSequence(texts);

      this.addExtraWithConf = true;
      return true;
    } else {
      return false;
    }
  }

  @Override
  public ExtensionValues getExtraExtensions(
      Map<ASN1ObjectIdentifier, ExtensionControl> extensionOccurences,
      X500Name requestedSubject, X500Name grantedSubject,
      Map<ASN1ObjectIdentifier, Extension> requestedExtensions,
      Date notBefore, Date notAfter, PublicCaInfo caInfo)
      throws CertprofileException, BadCertTemplateException {
    ExtensionValues extnValues = new ExtensionValues();

    if (addExtraWithoutConf) {
      ASN1ObjectIdentifier type = id_demo_without_conf;
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

    if (addExtraWithConf) {
      ASN1ObjectIdentifier type = id_demo_with_conf;
      ExtensionControl extnControl = extensionOccurences.get(type);
      if (extnControl != null) {
        if (sequence == null) {
          throw new IllegalStateException("Certprofile is not initialized");
        }

        ExtensionValue extnValue = new ExtensionValue(extnControl.isCritical(), sequence);
        extnValues.addExtension(type, extnValue);
      }
    }

    return extnValues.size() == 0 ? null : extnValues;
  } // method getExtensions

}
