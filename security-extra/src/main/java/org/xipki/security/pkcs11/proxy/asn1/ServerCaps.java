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

import java.io.IOException;
import java.math.BigInteger;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.util.Args;

/**
 * Server capability.
 *
 * <pre>
 * ServerCaps ::= SEQUENCE {
 *     readOnly      BOOLEAN,
 *     versions      SET OF ServerVersion }
 *
 * ServerVersion ::= INTEGER
 * </pre>
 *
 * @author Lijun Liao
 */
public class ServerCaps extends ProxyMessage {

  private final Set<Short> versions;

  private final boolean readOnly;

  public ServerCaps(boolean readOnly, Set<Short> versions) {
    this.readOnly = readOnly;
    this.versions = Collections.unmodifiableSet(Args.notEmpty(versions, "versions"));
  }

  private ServerCaps(ASN1Sequence seq)
      throws BadAsn1ObjectException {
    requireRange(seq, 2, 2);
    try {
      this.readOnly = ASN1Boolean.getInstance(seq.getObjectAt(0)).isTrue();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid readOnly: " + ex.getMessage(), ex);
    }

    ASN1Sequence vecVersions;
    try {
      vecVersions = ASN1Sequence.getInstance(seq.getObjectAt(1));
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid versions: " + ex.getMessage(), ex);
    }

    int count = vecVersions.size();

    Set<Short> tmpVersions = new HashSet<>(count * 2);
    for (int i = 0; i < count; i++) {
      ASN1Integer asn1Int;
      try {
        asn1Int = ASN1Integer.getInstance(vecVersions.getObjectAt(i));
      } catch (IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("invalid version: " + ex.getMessage(), ex);
      }
      tmpVersions.add(asn1Int.getValue().shortValue());
    }
    this.versions = Collections.unmodifiableSet(tmpVersions);
  }

  public static ServerCaps getInstance(Object obj)
      throws BadAsn1ObjectException {
    if (obj == null || obj instanceof ServerCaps) {
      return (ServerCaps) obj;
    }

    try {
      if (obj instanceof ASN1Sequence) {
        return new ServerCaps((ASN1Sequence) obj);
      } else if (obj instanceof byte[]) {
        return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
      } else {
        throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
      }
    } catch (IOException | IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
    }
  }

  public Set<Short> getVersions() {
    return versions;
  }

  public boolean isReadOnly() {
    return readOnly;
  }

  @Override
  public ASN1Primitive toASN1Primitive() {
    ASN1EncodableVector vecVersions = new ASN1EncodableVector();
    for (Short version : versions) {
      vecVersions.add(new ASN1Integer(BigInteger.valueOf(version)));
    }

    ASN1EncodableVector vec = new ASN1EncodableVector();
    vec.add(ASN1Boolean.getInstance(readOnly));
    vec.add(new DERSequence(vecVersions));
    return new DERSequence(vec);
  }
} // class ServerCaps
