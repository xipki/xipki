/*
 *
 * Copyright (c) 2013 - 2020 Lijun Liao
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

package org.xipki.security.pkcs11.proxy.asn1;

import org.bouncycastle.asn1.*;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11Slot.P11KeyUsage;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;

import java.io.IOException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

/**
 * Control how to create new PKCS#11 keypair / secret key.
 *
 * <pre>
 * NewKeyControl ::= SEQUENCE {
 *     label                  UTF8 STRING,
 *     id                 [0] OCTET STRING OPTIONAL,
 *     keyUsages          [1] SEQUENCE OF P11KEYUSAGE OPTIONAL,
 *     extractable        [2] EXPLICIT BOOLEAN OPTIONAL }
 *
 * P11KEYUSAGE ::= ENUMERATED {
 *       DECRYPT         (0),
 *       DERIVE          (1),
 *       SIGN            (2),
 *       SIGN_RECOVER    (3),
 *       UNWRAP          (4)}
 * </pre>
 *
 * @author Lijun Liao
 */
public class NewKeyControl extends ProxyMessage {

  private static final Map<Integer, P11KeyUsage> valueToUsageMap;

  private static final Map<P11KeyUsage, Integer> usageToValueMap;

  private final P11NewKeyControl control;

  static {
    valueToUsageMap = new HashMap<>(10);
    valueToUsageMap.put(0, P11KeyUsage.DECRYPT);
    valueToUsageMap.put(1, P11KeyUsage.DERIVE);
    valueToUsageMap.put(2, P11KeyUsage.SIGN);
    valueToUsageMap.put(3, P11KeyUsage.SIGN_RECOVER);
    valueToUsageMap.put(4, P11KeyUsage.UNWRAP);

    usageToValueMap = new HashMap<>(10);
    for (Entry<Integer, P11KeyUsage> entry : valueToUsageMap.entrySet()) {
      usageToValueMap.put(entry.getValue(), entry.getKey());
    }
  } // method static

  public NewKeyControl(P11NewKeyControl control) {
    this.control = Args.notNull(control, "control");
  }

  private NewKeyControl(ASN1Sequence seq)
      throws BadAsn1ObjectException {
    final int size = seq.size();
    Args.min(size, "seq.size", 1);
    String label = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();

    Set<P11KeyUsage> usages = new HashSet<>();
    byte[] id = null;
    Boolean extractable = null;

    for (int i = 1; i < size; i++) {
      ASN1Encodable obj = seq.getObjectAt(i);
      if (!(obj instanceof ASN1TaggedObject)) {
        continue;
      }

      ASN1TaggedObject tagObj = (ASN1TaggedObject) obj;
      int tagNo = tagObj.getTagNo();
      if (tagNo == 0) {
        id = DEROctetString.getInstance(tagObj.getBaseObject()).getOctets();
      } else if (tagNo == 1) {
        ASN1Sequence usageSeq = ASN1Sequence.getInstance(tagObj.getBaseObject());
        final int usageSize = usageSeq.size();
        for (int j = 0; j < usageSize; j++) {
          ASN1Enumerated usageEnum = ASN1Enumerated.getInstance(usageSeq.getObjectAt(j));
          int enumValue = usageEnum.getValue().intValue();
          P11KeyUsage usage = valueToUsageMap.get(enumValue);
          if (usage == null) {
            throw new IllegalArgumentException("invalid usage " + enumValue);
          }
          usages.add(usage);
        }
      } else if (tagNo == 2) {
        extractable = ASN1Boolean.getInstance(tagObj.getBaseObject()).isTrue();
      }
    }

    this.control = new P11NewKeyControl(id, label);
    this.control.setUsages(usages);
    this.control.setExtractable(extractable);
  } // constructor

  public static NewKeyControl getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof NewKeyControl) {
      return (NewKeyControl) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new NewKeyControl((ASN1Sequence) obj);
      } else if (obj instanceof byte[]) {
        return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
      } else {
        throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
      }
    } catch (IOException | IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("unable to parse object: " + ex.getMessage(), ex);
    }
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vector = new ASN1EncodableVector();
    vector.add(new DERUTF8String(control.getLabel()));

    byte[] id = control.getId();
    if (id != null) {
      vector.add(new DERTaggedObject(0, new DEROctetString(id)));
    }

    Set<P11KeyUsage> usages = control.getUsages();
    if (CollectionUtil.isNotEmpty(usages)) {
      ASN1EncodableVector asn1Usages = new ASN1EncodableVector();
      for (P11KeyUsage usage : usages) {
        int value = usageToValueMap.get(usage);
        asn1Usages.add(new ASN1Enumerated(value));
      }
      vector.add(new DERTaggedObject(1, new DERSequence(asn1Usages)));
    }

    if (control.getExtractable() != null) {
      vector.add(new DERTaggedObject(2, ASN1Boolean.getInstance(control.getExtractable())));
    }

    return new DERSequence(vector);
  }

  public P11NewKeyControl getControl() {
    return control;
  }

} // class NewKeyControl
