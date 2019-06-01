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

package org.xipki.security.pkcs11.proxy;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.util.Arrays;
import org.xipki.security.BadAsn1ObjectException;
import org.xipki.security.pkcs11.P11Slot.P11KeyUsage;
import org.xipki.security.pkcs11.P11Slot.P11NewKeyControl;
import org.xipki.security.pkcs11.P11Slot.P11NewObjectControl;
import org.xipki.security.pkcs11.P11IdentityId;
import org.xipki.security.pkcs11.P11ObjectIdentifier;
import org.xipki.security.pkcs11.P11SlotIdentifier;
import org.xipki.security.pkcs11.P11Params.P11RSAPkcsPssParams;
import org.xipki.util.Args;
import org.xipki.util.CollectionUtil;
import org.xipki.util.StringUtil;

/**
 * ASN.1 Messages communicated between the PKCS#11 proxy client and server.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */
public abstract class ProxyMessage extends ASN1Object {

  /**
   * Parameters to add certificate.
   *
   * <pre>
   * AddCertParams ::= SEQUENCE {
   *     slotId               P11SlotIdentifier,
   *     control              NewKeyControl,
   *     certificate          Certificate }
   * </pre>
   */
  public static class AddCertParams extends ProxyMessage {

    private final P11SlotIdentifier slotId;

    private final P11NewObjectControl control;

    private final Certificate certificate;

    public AddCertParams(P11SlotIdentifier slotId, P11NewObjectControl control,
        Certificate certificate) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.control = Args.notNull(control, "control");
      this.certificate = Args.notNull(certificate, "certificate");
    }

    public AddCertParams(P11SlotIdentifier slotId, P11NewObjectControl control,
        X509Certificate certificate) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.control = Args.notNull(control, "control");
      Args.notNull(certificate, "certificate");
      byte[] encoded;
      try {
        encoded = certificate.getEncoded();
      } catch (CertificateEncodingException ex) {
        throw new IllegalArgumentException("could not encode certificate: " + ex.getMessage(), ex);
      }
      this.certificate = Certificate.getInstance(encoded);
    }

    private AddCertParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 3, 3);
      int idx = 0;
      slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
      control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
      this.certificate = getCertificate0(seq.getObjectAt(idx++));
    }

    public static AddCertParams getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof AddCertParams) {
        return (AddCertParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new AddCertParams((ASN1Sequence) obj);
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
      vector.add(new SlotIdentifier(slotId));
      vector.add(new NewObjectControl(control));
      vector.add(certificate);
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
      return slotId;
    }

    public P11NewObjectControl getControl() {
      return control;
    }

    public Certificate getCertificate() {
      return certificate;
    }

  }

  /**
   * Definition of DigestSecretKeyTemplate.
   *
   * <pre>
   * DigestSecretKeyTemplate ::= SEQUENCE {
   *     slotId         SlotIdentifier,
   *     objectId       ObjectIdentifier,
   *     mechanism      Mechanism}
   * </pre>
   */
  public static class DigestSecretKeyTemplate extends ProxyMessage {

    private final SlotIdentifier slotId;

    private final ObjectIdentifier objectId;

    private final Mechanism mechanism;

    private DigestSecretKeyTemplate(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 3, 3);
      int idx = 0;
      this.slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++));
      this.objectId = ObjectIdentifier.getInstance(seq.getObjectAt(idx++));
      this.mechanism = Mechanism.getInstance(seq.getObjectAt(idx++));
    }

    public DigestSecretKeyTemplate(SlotIdentifier slotId, ObjectIdentifier objectId,
        long mechanism) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.objectId = Args.notNull(objectId, "objectId");
      this.mechanism = new Mechanism(mechanism, null);
    }

    public static DigestSecretKeyTemplate getInstance(Object obj)
        throws BadAsn1ObjectException {
      if (obj == null || obj instanceof DigestSecretKeyTemplate) {
        return (DigestSecretKeyTemplate) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new DigestSecretKeyTemplate((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(slotId);
      vector.add(objectId);
      vector.add(mechanism);
      return new DERSequence(vector);
    }

    public SlotIdentifier getSlotId() {
      return slotId;
    }

    public ObjectIdentifier getObjectId() {
      return objectId;
    }

    public Mechanism getMechanism() {
      return mechanism;
    }
  }

  /**
   * Parameters to generate RSA keypair.
   *
   * <pre>
   * GenRSAKeypairParams ::= SEQUENCE {
   *     slotId               P11SlotIdentifier,
   *     control              NewKeyControl,
   *     p                    INTEGER,
   *     q                    INTEGER,
   *     g                    INTEGER}
   * </pre>
   */
  // CHECKSTYLE:SKIP
  public static class GenDSAKeypairParams extends ProxyMessage {

    private final P11SlotIdentifier slotId;

    private final P11NewKeyControl control;

    private final BigInteger p; // CHECKSTYLE:SKIP

    private final BigInteger q; // CHECKSTYLE:SKIP

    private final BigInteger g; // CHECKSTYLE:SKIP

    public GenDSAKeypairParams(P11SlotIdentifier slotId, P11NewKeyControl control,
        BigInteger p, BigInteger q, BigInteger g) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.control = Args.notNull(control, "control");
      this.p = Args.notNull(p, "p");
      this.q = Args.notNull(q, "q");
      this.g = Args.notNull(g, "g");
    }

    private GenDSAKeypairParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 5, 5);
      int idx = 0;
      slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
      control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
      p = getInteger(seq.getObjectAt(idx++));
      q = getInteger(seq.getObjectAt(idx++));
      g = getInteger(seq.getObjectAt(idx++));
    }

    public static GenDSAKeypairParams getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof GenDSAKeypairParams) {
        return (GenDSAKeypairParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new GenDSAKeypairParams((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new SlotIdentifier(slotId));
      vector.add(new NewKeyControl(control));
      vector.add(new ASN1Integer(p));
      vector.add(new ASN1Integer(q));
      vector.add(new ASN1Integer(g));
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
      return slotId;
    }

    public P11NewKeyControl getControl() {
      return control;
    }

    public BigInteger getP() {
      return p;
    }

    public BigInteger getQ() {
      return q;
    }

    public BigInteger getG() {
      return g;
    }

  }

  /**
   * Parameters to generate EC keypair.
   *
   * <pre>
   * GenECKeypairParams ::= SEQUENCE {
   *     slotId               P11SlotIdentifier,
   *     control              NewKeyControl,
   *     curveId              OBJECT IDENTIFIER }
   * </pre>
   */
  // CHECKSTYLE:SKIP
  public static class GenECKeypairParams extends ProxyMessage {

    private final P11SlotIdentifier slotId;

    private final P11NewKeyControl control;

    private final ASN1ObjectIdentifier curveId;

    public GenECKeypairParams(P11SlotIdentifier slotId,
        P11NewKeyControl control, ASN1ObjectIdentifier curveId) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.control = Args.notNull(control, "control");
      this.curveId = Args.notNull(curveId, "curveId");
    }

    private GenECKeypairParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 3, 3);
      int idx = 0;
      slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
      control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
      curveId = getObjectIdentifier(seq.getObjectAt(idx++));
    }

    public static GenECKeypairParams getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof GenECKeypairParams) {
        return (GenECKeypairParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new GenECKeypairParams((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new SlotIdentifier(slotId));
      vector.add(new NewKeyControl(control));
      vector.add(curveId);
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
      return slotId;
    }

    public P11NewKeyControl getControl() {
      return control;
    }

    public ASN1ObjectIdentifier getCurveId() {
      return curveId;
    }

  }

  /**
   * Paramters to generate EC keypair.
   *
   * <pre>
   * GenECKeypairParams ::= SEQUENCE {
   *     slotId               P11SlotIdentifier,
   *     control              NewKeyControl,
   *     String               CurveName }
   * </pre>
   */
  // CHECKSTYLE:SKIP
  public static class GenECEdwardsOrMontgomeryKeypairParams extends ProxyMessage {

    private final P11SlotIdentifier slotId;

    private final P11NewKeyControl control;

    private final String curveName;

    public GenECEdwardsOrMontgomeryKeypairParams(P11SlotIdentifier slotId,
        P11NewKeyControl control, String curveName) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.control = Args.notNull(control, "control");
      this.curveName = Args.notBlank(curveName, "curveName");
    }

    private GenECEdwardsOrMontgomeryKeypairParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 3, 3);
      int idx = 0;
      slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
      control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
      curveName = DERPrintableString.getInstance(seq.getObjectAt(idx++)).getString();
    }

    public static GenECEdwardsOrMontgomeryKeypairParams getInstance(Object obj)
        throws BadAsn1ObjectException {
      if (obj == null || obj instanceof GenECEdwardsOrMontgomeryKeypairParams) {
        return (GenECEdwardsOrMontgomeryKeypairParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new GenECEdwardsOrMontgomeryKeypairParams((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new SlotIdentifier(slotId));
      vector.add(new NewKeyControl(control));
      vector.add(new DERPrintableString(curveName));
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
      return slotId;
    }

    public P11NewKeyControl getControl() {
      return control;
    }

    public String getCurveName() {
      return curveName;
    }

  }

  /**
   * Parameters to generate RSA keypair.
   *
   * <pre>
   * GenRSAKeypairParams ::= SEQUENCE {
   *     slotId               P11SlotIdentifier,
   *     control              NewKeyControl,
   *     keysize              INTEGER,
   *     publicExponent       INTEGER OPTIONAL }
   * </pre>
   */
  // CHECKSTYLE:SKIP
  public static class GenRSAKeypairParams extends ProxyMessage {

    private final P11SlotIdentifier slotId;

    private final P11NewKeyControl control;

    private final int keysize;

    private final BigInteger publicExponent;

    public GenRSAKeypairParams(P11SlotIdentifier slotId,
        P11NewKeyControl control, int keysize, BigInteger publicExponent) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.control = Args.notNull(control, "control");
      this.keysize = Args.min(keysize, "keysize", 1);
      this.publicExponent = publicExponent;
    }

    private GenRSAKeypairParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 3, 4);
      final int size = seq.size();
      int idx = 0;
      slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
      control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
      keysize = getInteger(seq.getObjectAt(idx++)).intValue();
      Args.min(keysize, "keysize", 1);

      publicExponent = (size > 3) ? getInteger(seq.getObjectAt(idx++)) : null;
    }

    public static GenRSAKeypairParams getInstance(Object obj)
        throws BadAsn1ObjectException {
      if (obj == null || obj instanceof GenRSAKeypairParams) {
        return (GenRSAKeypairParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new GenRSAKeypairParams((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new SlotIdentifier(slotId));
      vector.add(new NewKeyControl(control));
      vector.add(new ASN1Integer(keysize));
      if (publicExponent != null) {
        vector.add(new ASN1Integer(publicExponent));
      }
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
      return slotId;
    }

    public P11NewKeyControl getControl() {
      return control;
    }

    public int getKeysize() {
      return keysize;
    }

    public BigInteger getPublicExponent() {
      return publicExponent;
    }

  }

  /**
   * Parameters to generate secret key.
   *
   * <pre>
   * GenSecretKeyParams ::= SEQUENCE {
   *     slotId               P11SlotIdentifier,
   *     control              NewKeyControl,
   *     keyType              INTEGER,
   *     keysize              INTEGER }
   * </pre>
   */
  public static class GenSecretKeyParams extends ProxyMessage {

    private final P11SlotIdentifier slotId;

    private final P11NewKeyControl control;

    private final long keyType;

    private final int keysize;

    public GenSecretKeyParams(P11SlotIdentifier slotId, P11NewKeyControl control, long keyType,
        int keysize) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.control = Args.notNull(control, "control");
      this.keyType = keyType;
      this.keysize = Args.min(keysize, "keysize", 1);
    }

    private GenSecretKeyParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 4, 4);
      int idx = 0;
      slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
      control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
      keyType = getInteger(seq.getObjectAt(idx++)).longValue();
      keysize = getInteger(seq.getObjectAt(idx++)).intValue();
      Args.min(keysize, "keysize", 1);
    }

    public static GenSecretKeyParams getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof GenSecretKeyParams) {
        return (GenSecretKeyParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new GenSecretKeyParams((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new SlotIdentifier(slotId));
      vector.add(new NewKeyControl(control));
      vector.add(new ASN1Integer(keyType));
      vector.add(new ASN1Integer(keysize));
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
      return slotId;
    }

    public P11NewKeyControl getControl() {
      return control;
    }

    public long getKeyType() {
      return keyType;
    }

    public int getKeysize() {
      return keysize;
    }

  }

  /**
   * Parameters to generate SM2 keypair.
   *
   * <pre>
   * GenSM2KeypairParams ::= SEQUENCE {
   *     slotId               P11SlotIdentifier,
   *     control              NewKeyControl }
   * </pre>
   */
  // CHECKSTYLE:SKIP
  public static class GenSM2KeypairParams extends ProxyMessage {

    private final P11SlotIdentifier slotId;

    private final P11NewKeyControl control;

    public GenSM2KeypairParams(P11SlotIdentifier slotId, P11NewKeyControl control) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.control = Args.notNull(control, "control");
    }

    private GenSM2KeypairParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 2, 2);
      int idx = 0;
      slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
      control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
    }

    public static GenSM2KeypairParams getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof GenSM2KeypairParams) {
        return (GenSM2KeypairParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new GenSM2KeypairParams((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new SlotIdentifier(slotId));
      vector.add(new NewKeyControl(control));
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
      return slotId;
    }

    public P11NewKeyControl getControl() {
      return control;
    }

  }

  /**
   * Parameters to import secret key.
   *
   * <pre>
   * ImportSecretKeyParams ::= SEQUENCE {
   *     slotId               P11SlotIdentifier,
   *     control              NewKeyControl,
   *     keyType              INTEGER,
   *     keyValue             OCTET STRING}
   * </pre>
   */
  // CHECKSTYLE:SKIP
  public static class ImportSecretKeyParams extends ProxyMessage {

    private final P11SlotIdentifier slotId;

    private final P11NewKeyControl control;

    private final long keyType;

    private final byte[] keyValue;

    public ImportSecretKeyParams(P11SlotIdentifier slotId,
        P11NewKeyControl control, long keyType, byte[] keyValue) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.control = Args.notNull(control, "control");
      this.keyType = keyType;
      this.keyValue = Args.notNull(keyValue, "keyValue");
    }

    private ImportSecretKeyParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 4, 4);
      int idx = 0;
      slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
      control = NewKeyControl.getInstance(seq.getObjectAt(idx++)).getControl();
      keyType = getInteger(seq.getObjectAt(idx++)).longValue();
      keyValue = ASN1OctetString.getInstance(seq.getObjectAt(idx++)).getOctets();
    }

    public static ImportSecretKeyParams getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof ImportSecretKeyParams) {
        return (ImportSecretKeyParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new ImportSecretKeyParams((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new SlotIdentifier(slotId));
      vector.add(new ASN1Integer(keyType));
      vector.add(new DEROctetString(keyValue));
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
      return slotId;
    }

    public P11NewKeyControl getControl() {
      return control;
    }

    public long getKeyType() {
      return keyType;
    }

    public byte[] getKeyValue() {
      return Arrays.copyOf(keyValue, keyValue.length);
    }

  }

  /**
   * Definition of Mechanism.
   *
   * <pre>
   * Mechanism ::= SEQUENCE {
   *     mechanism     INTEGER,
   *     params        P11Params OPTIONAL }
   * </pre>
   */
  public static class Mechanism extends ProxyMessage {

    private final long mechanism;

    private final P11Params params;

    public Mechanism(long mechanism, P11Params params) {
      this.mechanism = mechanism;
      this.params = params;
    }

    private Mechanism(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 1, 2);
      int size = seq.size();
      int idx = 0;
      this.mechanism = getInteger(seq.getObjectAt(idx++)).longValue();
      this.params = (size > 1)  ? P11Params.getInstance(seq.getObjectAt(idx++)) : null;
    }

    public static Mechanism getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof Mechanism) {
        return (Mechanism) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new Mechanism((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new ASN1Integer(mechanism));
      if (params != null) {
        vector.add(params);
      }
      return new DERSequence(vector);
    }

    public long getMechanism() {
      return mechanism;
    }

    public P11Params getParams() {
      return params;
    }

  }

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
   */
  public static class NewKeyControl extends ProxyMessage {

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
      for (Integer value : valueToUsageMap.keySet()) {
        P11KeyUsage usage = valueToUsageMap.get(value);
        usageToValueMap.put(usage, value);
      }
    }

    public NewKeyControl(P11NewKeyControl control) {
      this.control = Args.notNull(control, "control");
    }

    private NewKeyControl(ASN1Sequence seq) throws BadAsn1ObjectException {
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
          id = DEROctetString.getInstance(tagObj.getObject()).getOctets();
        } else if (tagNo == 1) {
          ASN1Sequence usageSeq = ASN1Sequence.getInstance(tagObj.getObject());
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
          extractable = ASN1Boolean.getInstance(tagObj.getObject()).isTrue();
        }
      }

      this.control = new P11NewKeyControl(id, label);
      this.control.setUsages(usages);
      this.control.setExtractable(extractable);
    }

    public static NewKeyControl getInstance(Object obj) throws BadAsn1ObjectException {
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
      if (CollectionUtil.isNonEmpty(usages)) {
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

  }

  /**
   * Control how to create new PKCS#11 object.
   *
   * <pre>
   * NewKeyControl ::= SEQUENCE {
   *     label                  UTF8 STRING,
   *     id                 [0] OCTET STRING OPTIONAL }
   * </pre>
   */
  public static class NewObjectControl extends ProxyMessage {

    private final P11NewObjectControl control;

    public NewObjectControl(P11NewObjectControl control) {
      this.control = Args.notNull(control, "control");
    }

    private NewObjectControl(ASN1Sequence seq) throws BadAsn1ObjectException {
      final int size = seq.size();
      Args.min(size, "seq.size", 1);
      String label = DERUTF8String.getInstance(seq.getObjectAt(0)).getString();
      byte[] id = null;

      for (int i = 1; i < size; i++) {
        ASN1Encodable obj = seq.getObjectAt(i);
        if (obj instanceof ASN1TaggedObject) {
          continue;
        }

        ASN1TaggedObject tagObj = (ASN1TaggedObject) obj;
        int tagNo = tagObj.getTagNo();
        if (tagNo == 0) {
          id = DEROctetString.getInstance(tagObj.getObject()).getOctets();
        }
      }

      this.control = new P11NewKeyControl(id, label);
    }

    public static NewObjectControl getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof NewObjectControl) {
        return (NewObjectControl) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new NewObjectControl((ASN1Sequence) obj);
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

      return new DERSequence(vector);
    }

    public P11NewObjectControl getControl() {
      return control;
    }

  }

  /**
   * Definition of ObjectIdAndCert.
   *
   * <pre>
   * ObjectIdAndCert ::= SEQUENCE {
   *     slotId         SlotIdentifier,
   *     objectId       ObjectIdentifier,
   *     certificate    Certificate }
   * </pre>
   */
  public static class ObjectIdAndCert extends ProxyMessage {

    private final SlotIdentifier slotId;

    private final ObjectIdentifier objectId;

    private final Certificate certificate;

    public ObjectIdAndCert(SlotIdentifier slotId, ObjectIdentifier objectId,
        Certificate certificate) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.objectId = Args.notNull(objectId, "objectId");
      this.certificate = Args.notNull(certificate, "certificate");
    }

    public ObjectIdAndCert(SlotIdentifier slotId, ObjectIdentifier objectId,
        X509Certificate certificate) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.objectId = Args.notNull(objectId, "objectId");
      Args.notNull(certificate, "certificate");
      byte[] encoded;
      try {
        encoded = certificate.getEncoded();
      } catch (CertificateEncodingException ex) {
        throw new IllegalArgumentException("could not encode certificate: " + ex.getMessage(), ex);
      }
      this.certificate = Certificate.getInstance(encoded);
    }

    private ObjectIdAndCert(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 3, 3);
      int idx = 0;
      this.slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++));
      this.objectId = ObjectIdentifier.getInstance(seq.getObjectAt(idx++));
      this.certificate = getCertificate0(seq.getObjectAt(idx++));
    }

    public static ObjectIdAndCert getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof ObjectIdAndCert) {
        return (ObjectIdAndCert) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new ObjectIdAndCert((ASN1Sequence) obj);
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
      vector.add(slotId);
      vector.add(objectId);
      vector.add(certificate);
      return new DERSequence(vector);
    }

    public SlotIdentifier getSlotId() {
      return slotId;
    }

    public ObjectIdentifier getObjectId() {
      return objectId;
    }

    public Certificate getCertificate() {
      return certificate;
    }

  }

  /**
   * Identifier of the PKCS#11 identity.
   *
   * <pre>
   * IdentityIdentifer ::= SEQUENCE {
   *     slotId              SlotIdentifier,
   *     keyId               ObjectIdentifier,
   *     publicKeyLabel  [1] UTF8 STRING OPTIONAL,
   *     certLabel       [2] UTF8 STRING OPTIONAL }
   * </pre>
   */
  public static class IdentityId extends ProxyMessage {

    private final P11IdentityId value;

    public IdentityId(P11IdentityId value) {
      this.value = Args.notNull(value, "value");
    }

    private IdentityId(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 2, 4);
      P11SlotIdentifier slotId =
          SlotIdentifier.getInstance(seq.getObjectAt(0)).getValue();
      P11ObjectIdentifier keyId =
          ObjectIdentifier.getInstance(seq.getObjectAt(1)).getValue();
      String publicKeyLabel = null;
      String certLabel = null;

      final int n = seq.size();
      for (int i = 2; i < n; i++) {
        ASN1Encodable asn1 = seq.getObjectAt(i);
        if (asn1 instanceof ASN1TaggedObject) {
          ASN1TaggedObject tagAsn1 = (ASN1TaggedObject) asn1;
          int tag = tagAsn1.getTagNo();
          if (tag == 1) {
            publicKeyLabel = DERUTF8String.getInstance(tagAsn1.getObject()).getString();
          } else if (tag == 2) {
            certLabel = DERUTF8String.getInstance(tagAsn1.getObject()).getString();
          }
        }

      }

      this.value = new P11IdentityId(slotId, keyId, publicKeyLabel, certLabel);
    }

    public static IdentityId getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof IdentityId) {
        return (IdentityId) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new IdentityId((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new SlotIdentifier(value.getSlotId()));
      vector.add(new ObjectIdentifier(value.getKeyId()));

      if (value.getPublicKeyId() != null) {
        String label = value.getPublicKeyId().getLabel();
        vector.add(new DERTaggedObject(true, 1, new DERUTF8String(label)));
      }

      if (value.getCertId() != null) {
        String label = value.getCertId().getLabel();
        vector.add(new DERTaggedObject(true, 2, new DERUTF8String(label)));
      }

      return new DERSequence(vector);
    }

    public P11IdentityId getValue() {
      return value;
    }

  }

  /**
   * Identifier of PKCS#11 object.
   *
   * <pre>
   * P11ObjectIdentifier ::= SEQUENCE {
   *     id        OCTET STRING,
   *     label     UTF8STRING }
   * </pre>
   */
  public static class ObjectIdentifier extends ProxyMessage {

    private final P11ObjectIdentifier value;

    public ObjectIdentifier(P11ObjectIdentifier value) {
      this.value = Args.notNull(value, "value");
    }

    private ObjectIdentifier(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 2, 2);
      int idx = 0;
      byte[] id = getOctetStringBytes(seq.getObjectAt(idx++));
      String label = getUtf8String(seq.getObjectAt(idx++));
      this.value = new P11ObjectIdentifier(id, label);
    }

    public static ObjectIdentifier getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof ObjectIdentifier) {
        return (ObjectIdentifier) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new ObjectIdentifier((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      vec.add(new DEROctetString(value.getId()));
      vec.add(new DERUTF8String(value.getLabel()));
      return new DERSequence(vec);
    }

    public P11ObjectIdentifier getValue() {
      return value;
    }

  }

  /**
   * List of {@link ObjectIdentifier}s.
   *
   * <pre>
   * P11ObjectIdentifiers ::= SEQUENCE OF P11ObjectIdentifier
   * </pre>
   */
  public static class ObjectIdentifiers extends ProxyMessage {

    private final List<ObjectIdentifier> objectIds;

    public ObjectIdentifiers(List<ObjectIdentifier> objectIds) {
      this.objectIds = Args.notNull(objectIds, "objectIds");
    }

    private ObjectIdentifiers(ASN1Sequence seq) throws BadAsn1ObjectException {
      this.objectIds = new LinkedList<>();
      final int size = seq.size();
      for (int i = 0; i < size; i++) {
        objectIds.add(ObjectIdentifier.getInstance(seq.getObjectAt(i)));
      }
    }

    public static ObjectIdentifiers getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof ObjectIdentifiers) {
        return (ObjectIdentifiers) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new ObjectIdentifiers((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vec = new ASN1EncodableVector();
      for (ObjectIdentifier objectId : objectIds) {
        vec.add(objectId);
      }
      return new DERSequence(vec);
    }

    public List<ObjectIdentifier> getObjectIds() {
      return objectIds;
    }

  }

  /**
   * ASN.1 PKCS#11 params.
   *
   * <pre>
   * P11Params ::= CHOICE {
   *     rsaPkcsPssParams   [0]  RSA-PKCS-PSS-Parameters,
   *     opaqueParams       [1]  OCTET-STRING,
   *     iv                 [2]  IV }
   * </pre>
   */
  public static class P11Params extends ProxyMessage {

    public static final int TAG_RSA_PKCS_PSS = 0;

    public static final int TAG_OPAQUE = 1;

    public static final int TAG_IV = 2;

    private final int tagNo;
    private final ASN1Encodable p11Params;

    public P11Params(int tagNo, ASN1Encodable p11Params) {
      this.tagNo = tagNo;
      this.p11Params = Args.notNull(p11Params, "p11Params");
    }

    private P11Params(ASN1TaggedObject taggedObject) throws BadAsn1ObjectException {
      this.tagNo = taggedObject.getTagNo();
      this.p11Params = taggedObject.getObject();
    }

    public static P11Params getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof P11Params) {
        return (P11Params) obj;
      }

      try {
        if (obj instanceof ASN1TaggedObject) {
          return new P11Params((ASN1TaggedObject) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      return new DERTaggedObject(tagNo, p11Params);
    }

    public int getTagNo() {
      return tagNo;
    }

    public ASN1Encodable getP11Params() {
      return p11Params;
    }

  }

  /**
   * Slot identifier and Object identifier.
   *
   * <pre>
   * SlotIdAndObjectId ::= SEQUENCE {
   *     slotId     SlotIdentifier,
   *     objectId   ObjectIdentifier}
   * </pre>
   */
  public static class SlotIdAndObjectId extends ProxyMessage {

    private final SlotIdentifier slotId;

    private final ObjectIdentifier objectId;

    public SlotIdAndObjectId(P11SlotIdentifier slotId, P11ObjectIdentifier objectId) {
      Args.notNull(slotId, "slotId");
      Args.notNull(objectId, "objectId");

      this.slotId = new SlotIdentifier(slotId);
      this.objectId = new ObjectIdentifier(objectId);
    }

    public SlotIdAndObjectId(SlotIdentifier slotId,
        ObjectIdentifier objectId) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.objectId = Args.notNull(objectId, "objectId");
    }

    private SlotIdAndObjectId(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 2, 2);
      int idx = 0;
      this.slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++));
      this.objectId = ObjectIdentifier.getInstance(seq.getObjectAt(idx++));
    }

    public static SlotIdAndObjectId getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof SlotIdAndObjectId) {
        return (SlotIdAndObjectId) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new SlotIdAndObjectId((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      return new DERSequence(new ASN1Encodable[]{slotId, objectId});
    }

    public SlotIdentifier getSlotId() {
      return slotId;
    }

    public ObjectIdentifier getObjectId() {
      return objectId;
    }

  }

  /**
   * Slot identifier.
   *
   * <pre>
   * SlotIdentifier ::= SEQUENCE {
   *     id         INTEGER,
   *     index      INTEGER }
   * </pre>
   */
  public static class SlotIdentifier extends ProxyMessage {

    private final P11SlotIdentifier value;

    public SlotIdentifier(P11SlotIdentifier value) {
      this.value = Args.notNull(value, "value");
    }

    private SlotIdentifier(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 2, 2);
      int idx = 0;
      long id = getInteger(seq.getObjectAt(idx++)).longValue();
      int index = getInteger(seq.getObjectAt(idx++)).intValue();
      this.value = new P11SlotIdentifier(index, id);
    }

    public static SlotIdentifier getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof SlotIdentifier) {
        return (SlotIdentifier) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new SlotIdentifier((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new ASN1Integer(value.getId()));
      vector.add(new ASN1Integer(value.getIndex()));
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getValue() {
      return value;
    }

  }

  /**
   * Parameters to remove objects.
   *
   * <pre>
   * RemoveObjectsParams ::= SEQUENCE {
   *     slotId     SlotIdentifier,
   *     id         OCTET STRING OPTIONAL, -- at least one of id and label must be present
   *     label      UTF8String OPTIONAL }
   * </pre>
   */
  public static class RemoveObjectsParams extends ProxyMessage {

    private final P11SlotIdentifier slotId;

    private final byte[] objectId;

    private final String objectLabel;

    public RemoveObjectsParams(P11SlotIdentifier slotId, byte[] objectId, String objectLabel) {
      Args.notNull(slotId, "slotId");
      if ((objectId == null || objectId.length == 0) && StringUtil.isBlank(objectLabel)) {
        throw new IllegalArgumentException(
            "at least one of objectId and objectLabel must not be null");
      }

      this.objectId = objectId;
      this.objectLabel = objectLabel;
      this.slotId = slotId;
    }

    private RemoveObjectsParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 2, 3);
      int idx = 0;
      slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++)).getValue();
      final int size = seq.size();
      ASN1Encodable asn1Id = null;
      ASN1Encodable asn1Label = null;
      if (size == 2) {
        ASN1Encodable asn1 = seq.getObjectAt(1);
        if (asn1 instanceof ASN1String) {
          asn1Label = asn1;
        } else {
          asn1Id = asn1;
        }
      } else {
        asn1Id = seq.getObjectAt(idx++);
        asn1Label = seq.getObjectAt(idx++);
      }

      objectId = (asn1Id == null) ? null : getOctetStringBytes(asn1Id);
      objectLabel = (asn1Label == null) ? null : getUtf8String(seq.getObjectAt(idx++));

      if ((objectId == null || objectId.length == 0) && StringUtil.isBlank(objectLabel)) {
        throw new BadAsn1ObjectException("invalid object RemoveObjectsParams: "
            + "at least one of id and label must not be null");
      }
    }

    public static RemoveObjectsParams getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof RemoveObjectsParams) {
        return (RemoveObjectsParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new RemoveObjectsParams((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new SlotIdentifier(slotId));
      vector.add(new DERUTF8String(objectLabel));
      return new DERSequence(vector);
    }

    public P11SlotIdentifier getSlotId() {
      return slotId;
    }

    public byte[] getOjectId() {
      return objectId == null ? null : Arrays.copyOf(objectId, objectId.length);
    }

    public String getObjectLabel() {
      return objectLabel;
    }

  }

  /**
   * Parameters to create RSAPkcsPss signature.
   *
   * <pre>
   * RSAPkcsPssParams ::= SEQUENCE {
   *     contentHash       INTEGER,
   *     mgfHash           INTEGER,
   *     saltLength        INTEGER }
   * </pre>
   */
  // CHECKSTYLE:SKIP
  public static class RSAPkcsPssParams extends ProxyMessage {

    private final P11RSAPkcsPssParams pkcsPssParams;

    public RSAPkcsPssParams(P11RSAPkcsPssParams pkcsPssParams) {
      this.pkcsPssParams = Args.notNull(pkcsPssParams, "pkcsPssParams");
    }

    private RSAPkcsPssParams(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 3, 3);
      int idx = 0;
      long contentHash = getInteger(seq.getObjectAt(idx++)).longValue();
      long mgfHash = getInteger(seq.getObjectAt(idx++)).longValue();
      int saltLength = getInteger(seq.getObjectAt(idx++)).intValue();
      this.pkcsPssParams = new P11RSAPkcsPssParams(contentHash, mgfHash, saltLength);
    } // constructor

    public static RSAPkcsPssParams getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof RSAPkcsPssParams) {
        return (RSAPkcsPssParams) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new RSAPkcsPssParams((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(), ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(new ASN1Integer(pkcsPssParams.getHashAlgorithm()));
      vector.add(new ASN1Integer(pkcsPssParams.getMaskGenerationFunction()));
      vector.add(new ASN1Integer(pkcsPssParams.getSaltLength()));
      return new DERSequence(vector);
    }

    public P11RSAPkcsPssParams getPkcsPssParams() {
      return pkcsPssParams;
    }

  }

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
   */
  public static class ServerCaps extends ProxyMessage {

    private final Set<Short> versions;

    private final boolean readOnly;

    public ServerCaps(boolean readOnly, Set<Short> versions) {
      this.readOnly = readOnly;
      this.versions = Collections.unmodifiableSet(Args.notEmpty(versions, "versions"));
    }

    private ServerCaps(ASN1Sequence seq) throws BadAsn1ObjectException {
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

    public static ServerCaps getInstance(Object obj) throws BadAsn1ObjectException {
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
  }

  /**
   * Definition of SignTemplate.
   *
   * <pre>
   * SignTemplate ::= SEQUENCE {
   *     slotId         SlotIdentifier,
   *     objectId       ObjectIdentifier,
   *     mechanism      Mechanism,
   *     message        OCTET STRING }
   * </pre>
   */
  public static class SignTemplate extends ProxyMessage {

    private final SlotIdentifier slotId;

    private final ObjectIdentifier objectId;

    private final Mechanism mechanism;

    private final byte[] message;

    private SignTemplate(ASN1Sequence seq) throws BadAsn1ObjectException {
      requireRange(seq, 4, 4);
      int idx = 0;
      this.slotId = SlotIdentifier.getInstance(seq.getObjectAt(idx++));
      this.objectId = ObjectIdentifier.getInstance(seq.getObjectAt(idx++));
      this.mechanism = Mechanism.getInstance(seq.getObjectAt(idx++));
      this.message = getOctetStringBytes(seq.getObjectAt(idx++));
    }

    public SignTemplate(SlotIdentifier slotId, ObjectIdentifier objectId,
        long mechanism, P11Params parameter, byte[] message) {
      this.slotId = Args.notNull(slotId, "slotId");
      this.objectId = Args.notNull(objectId, "objectId");
      this.message = Args.notNull(message, "message");
      this.mechanism = new Mechanism(mechanism, parameter);
    }

    public static SignTemplate getInstance(Object obj) throws BadAsn1ObjectException {
      if (obj == null || obj instanceof SignTemplate) {
        return (SignTemplate) obj;
      }

      try {
        if (obj instanceof ASN1Sequence) {
          return new SignTemplate((ASN1Sequence) obj);
        } else if (obj instanceof byte[]) {
          return getInstance(ASN1Primitive.fromByteArray((byte[]) obj));
        } else {
          throw new BadAsn1ObjectException("unknown object: " + obj.getClass().getName());
        }
      } catch (IOException | IllegalArgumentException ex) {
        throw new BadAsn1ObjectException("unable to parse encoded object: " + ex.getMessage(),
            ex);
      }
    }

    @Override
    public ASN1Primitive toASN1Primitive() {
      ASN1EncodableVector vector = new ASN1EncodableVector();
      vector.add(slotId);
      vector.add(objectId);
      vector.add(mechanism);
      vector.add(new DEROctetString(message));
      return new DERSequence(vector);
    }

    public byte[] getMessage() {
      return message;
    }

    public SlotIdentifier getSlotId() {
      return slotId;
    }

    public ObjectIdentifier getObjectId() {
      return objectId;
    }

    public Mechanism getMechanism() {
      return mechanism;
    }
  }

  private static void requireRange(ASN1Sequence seq, int minSize, int maxSize)
      throws BadAsn1ObjectException {
    int size = seq.size();
    if (size < minSize || size > maxSize) {
      String msg = String.format("seq.size() must not be out of the range [%d, %d]: %d",
          minSize, maxSize, size);
      throw new IllegalArgumentException(msg);
    }
  }

  private static Certificate getCertificate0(ASN1Encodable object) throws BadAsn1ObjectException {
    try {
      return Certificate.getInstance(object);
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object Certificate: " + ex.getMessage(), ex);
    }
  }

  private static BigInteger getInteger(ASN1Encodable object) throws BadAsn1ObjectException {
    try {
      return ASN1Integer.getInstance(object).getValue();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object ASN1Integer: " + ex.getMessage(), ex);
    }
  }

  private static String getUtf8String(ASN1Encodable object) throws BadAsn1ObjectException {
    try {
      return DERUTF8String.getInstance(object).getString();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object UTF8String: " + ex.getMessage(), ex);
    }
  }

  public static byte[] getOctetStringBytes(ASN1Encodable object) throws BadAsn1ObjectException {
    try {
      return DEROctetString.getInstance(object).getOctets();
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object OctetString: " + ex.getMessage(), ex);
    }
  }

  private static ASN1ObjectIdentifier getObjectIdentifier(ASN1Encodable object)
      throws BadAsn1ObjectException {
    try {
      return ASN1ObjectIdentifier.getInstance(object);
    } catch (IllegalArgumentException ex) {
      throw new BadAsn1ObjectException("invalid object ObjectIdentifier: " + ex.getMessage(), ex);
    }
  }

}

