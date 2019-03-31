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

package org.xipki.ca.certprofile.test;

import java.util.Date;
import java.util.Map;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.CertificationRequest;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extensions;
import org.xipki.ca.certprofile.xijson.ExtensionSyntaxChecker;
import org.xipki.ca.certprofile.xijson.XijsonCertprofile;
import org.xipki.ca.certprofile.xijson.conf.ExtensionType.ExtnSyntax;
import org.xipki.security.ObjectIdentifiers;
import org.xipki.util.ConfPairs;
import org.xipki.util.IoUtil;
import org.xipki.util.Validity;

/**
 * TODO.
 * @author Lijun Liao
 */

public class DummyMain {

  public static void main(String[] args) {
    try {
      Validity validity = Validity.getInstance("395d");
      Date date = validity.add(new Date());
      System.out.println(date);

      RDN rdn = new RDN(ObjectIdentifiers.DN.uniqueIdentifier, new DERUTF8String("hello"));
      X500Name name = new X500Name(new RDN[] {rdn});
      System.out.println(name.toString());

      name = new X500Name("UniqueIdentifier=hello");
      System.out.println(name.toString());

      System.out.println(ObjectIdentifiers.Extn.id_ad_caRepository.getId());
      ConfPairs cf = new ConfPairs();
      cf.putPair("a", "b=c");
      System.out.println(cf.getEncoded());
      /*
      ASN1Encodable inner = new X500Name("CN=abc");

      ASN1TaggedObject taggedObj = new DERTaggedObject(false, 1, inner);
      byte[] encoded = taggedObj.getEncoded();
      ASN1TaggedObject obj2 = ASN1TaggedObject.getInstance(encoded);
      ASN1Encodable inner2 = X500Name.getInstance(obj2.getObject());

      inner = new ASN1Integer(10);

      taggedObj = new DERTaggedObject(false, 1, inner);
      encoded = taggedObj.getEncoded();

      obj2 = ASN1TaggedObject.getInstance(encoded);
      inner2 = DERPrintableString.getInstance(obj2.getObject());
      */

      byte[] encodedCsr = IoUtil.read(
          "~/source/xipki/assemblies/xipki-qa/target/xipki-qa-5.1.1-SNAPSHOT/output/"
          + "apple-wwdr1.csr");
      CertificationRequest csr = CertificationRequest.getInstance(encodedCsr);

      ASN1Set attrs = csr.getCertificationRequestInfo().getAttributes();

      Extensions extns = null;
      for (int i = 0; i < attrs.size(); i++) {
        Attribute attr = Attribute.getInstance(attrs.getObjectAt(i));
        if (PKCSObjectIdentifiers.pkcs_9_at_extensionRequest.equals(attr.getAttrType())) {
          extns = Extensions.getInstance(attr.getAttributeValues()[0]);
          break;
        }
      }

      if (extns == null) {
        throw new Exception("no extension is present");
      }

      XijsonCertprofile certprof = new XijsonCertprofile();
      String data = new String(IoUtil.read("tmp/certprofile-apple-wwdr.json"));
      certprof.initialize(data);

      Map<ASN1ObjectIdentifier, ExtnSyntax> syntaxes = certprof.getExtensionsWithSyntax();

      ASN1ObjectIdentifier[] oids = extns.getExtensionOIDs();
      for (ASN1ObjectIdentifier oid : oids) {
        ExtnSyntax syntax = syntaxes.get(oid);
        if (syntax == null) {
          continue;
        }

        System.out.println("checking " + oid.getId());
        ExtensionSyntaxChecker.checkExtension(oid.getId(), extns.getExtension(oid).getParsedValue(),
            syntax);
        System.out.println(" checked " + oid.getId());
      }

      certprof.close();
    } catch (Exception ex) {
      ex.printStackTrace();
    }
  }

}
