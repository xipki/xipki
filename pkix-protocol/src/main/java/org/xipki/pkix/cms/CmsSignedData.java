// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.pkix.cms;

import org.xipki.pkix.asn1.cms.*;
import org.xipki.pkix.asn1.x509.Attribute;
import org.xipki.pkix.asn1.x509.Certificate;
import org.xipki.pkix.asn1.x509.CertificateList;
import org.xipki.codec.asn1.Asn1OctetString;
import org.xipki.codec.asn1.Asn1Oid;
import org.xipki.codec.asn1.Asn1Primitive;
import org.xipki.codec.crypto.ContentSigner;
import org.xipki.codec.asn1.crypto.AlgorithmIdentifier;
import org.xipki.codec.asn1.oid.CmsOIDs;
import org.xipki.codec.util.Args;
import org.xipki.codec.exception.CodecException;
import org.xipki.util.exception.PkixException;

import java.security.SignatureException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * CMS SignedData (RFC 5652, section 5).
 *
 * @author Lijun Liao (xipki)
 */
public class CmsSignedData {

  private final ContentInfo contentInfo;

  private final SignedData signedData;

  private final Asn1Oid contentType;

  private final byte[] content;

  private final List<CmsSigner> signers;

  public CmsSignedData(byte[] encoded) throws PkixException {
    this(parseContentInfo(encoded));
  }

  public CmsSignedData(ContentInfo contentInfo) throws PkixException {
    this.contentInfo = Args.notNull(contentInfo, "contentInfo");
    if (!CmsOIDs.signedData.equals(contentInfo.getContentType())) {
      throw new PkixException("content type is not id-signedData, but "
          + contentInfo.getContentType().getId());
    }

    try {
      this.signedData = SignedData.fromAsn1(contentInfo.getContent().asSequence());
    } catch (CodecException | RuntimeException e) {
      throw new PkixException("malformed SignedData: " + e.getMessage(), e);
    }

    ContentInfo encapContentInfo = signedData.getEncapContentInfo();
    this.contentType = encapContentInfo.getContentType();
    Asn1Primitive eContent = encapContentInfo.getContent();
    if (eContent == null) {
      this.content = null;
    } else if (eContent instanceof Asn1OctetString) {
      this.content = ((Asn1OctetString) eContent).getOctets();
    } else {
      this.content = eContent.getEncoded();
    }

    List<CmsSigner> list = new ArrayList<>(signedData.getSignerInfos().size());
    for (SignerInfo info : signedData.getSignerInfos()) {
      list.add(new CmsSigner(info, contentType, content));
    }
    this.signers = Collections.unmodifiableList(list);
  }

  private static ContentInfo parseContentInfo(byte[] encoded) throws PkixException {
    try {
      return ContentInfo.fromEncoded(Args.notNull(encoded, "encoded"));
    } catch (CodecException | RuntimeException e) {
      throw new PkixException("malformed ContentInfo: " + e.getMessage(), e);
    }
  }

  /**
   * Returns the type of the encapsulated content.
   * @return the type of the encapsulated content.
   */
  public Asn1Oid getContentType() {
    return contentType;
  }

  /**
   * Returns the encapsulated content.
   * @return the encapsulated content, or {@code null} if absent.
   */
  public byte[] getContent() {
    return content;
  }

  public List<CmsSigner> getSigners() {
    return signers;
  }

  public List<Certificate> getCertificates() {
    CertificateChoice.Set0 choices = signedData.getCertificates();
    List<Certificate> list = new ArrayList<>();
    if (choices != null) {
      for (CertificateChoice choice : choices) {
        if (choice.hasV3Cert()) {
          list.add(choice.getCertificate());
        }
      }
    }
    return list;
  }

  public SignedData getSignedData() {
    return signedData;
  }

  public ContentInfo toASN1Structure() {
    return contentInfo;
  }

  public byte[] getEncoded() {
    return contentInfo.getEncoded();
  }

  /**
   * Builder of the CMS SignedData.
   *
   * <p>Each signer gets the signed attributes content-type, signing-time, message-digest and
   * cmsAlgorithmProtect (RFC 6211), unless given by the caller.
   *
   * @author Lijun Liao (xipki)
   */
  public static class Builder {

    private static class SignerEntry {
      private final ContentSigner signer;
      private final Certificate cert;
      private final AlgorithmIdentifier digestAlgorithm;
      private final Attributes signedAttributes;
      private final Attributes unsignedAttributes;

      private SignerEntry(ContentSigner signer, Certificate cert,
                          AlgorithmIdentifier digestAlgorithm,
                          Attributes signedAttributes, Attributes unsignedAttributes) {
        this.signer = signer;
        this.cert = cert;
        this.digestAlgorithm = digestAlgorithm;
        this.signedAttributes = signedAttributes;
        this.unsignedAttributes = unsignedAttributes;
      }
    }

    private Asn1Oid contentType = CmsOIDs.data;

    private byte[] content;

    private boolean encapsulate = true;

    private final List<CertificateChoice> certs = new ArrayList<>();

    private final List<RevocationInfoChoice> crls = new ArrayList<>();

    private final List<SignerEntry> signers = new ArrayList<>();

    /**
     * Sets the content to be signed. Without content, the eContent is absent, and the signers sign
     * the empty content, e.g. the SCEP CertRep with status FAILURE.
     *
     * @param contentType the type of the content.
     * @param content the content.
     * @param encapsulate whether to encapsulate the content in the SignedData.
     * @return this builder.
     */
    public Builder setContent(Asn1Oid contentType, byte[] content, boolean encapsulate) {
      this.contentType = Args.notNull(contentType, "contentType");
      this.content = Args.notNull(content, "content");
      this.encapsulate = encapsulate;
      return this;
    }

    public Builder addCertificate(Certificate cert) {
      certs.add(CertificateChoice.ofCertificate(Args.notNull(cert, "cert")));
      return this;
    }

    public Builder addCRL(CertificateList crl) {
      crls.add(RevocationInfoChoice.ofCrl(Args.notNull(crl, "crl")));
      return this;
    }

    /**
     * Adds a signer, identified by the issuer and serial number of its certificate.
     *
     * @param signer the signer.
     * @param signerCert the certificate of the signer.
     * @param digestAlgorithm the digest algorithm.
     * @param signedAttributes the signed attributes, may be {@code null}.
     * @param unsignedAttributes the unsigned attributes, may be {@code null}.
     * @return this builder.
     */
    public Builder addSigner(
        ContentSigner signer, Certificate signerCert, AlgorithmIdentifier digestAlgorithm,
        Attributes signedAttributes, Attributes unsignedAttributes) {
      signers.add(new SignerEntry(Args.notNull(signer, "signer"),
          Args.notNull(signerCert, "signerCert"), Args.notNull(digestAlgorithm, "digestAlgorithm"),
          signedAttributes, unsignedAttributes));
      return this;
    }

    public CmsSignedData build() throws PkixException {
      Set<AlgorithmIdentifier> digestAlgs = new LinkedHashSet<>();
      List<SignerInfo> signerInfos = new ArrayList<>(signers.size());
      for (SignerEntry entry : signers) {
        digestAlgs.add(entry.digestAlgorithm);
        signerInfos.add(buildSignerInfo(entry));
      }

      Asn1OctetString eContent = (content != null && encapsulate)
          ? new Asn1OctetString(content) : null;

      SignedData signedData = new SignedData(
          new AlgorithmIdentifier.Set0(digestAlgs),
          new ContentInfo(contentType, eContent),
          certs.isEmpty() ? null : new CertificateChoice.Set0(certs),
          crls.isEmpty() ? null : new RevocationInfoChoice.Set0(crls),
          new SignerInfos(signerInfos));

      return new CmsSignedData(ContentInfo.build(CmsOIDs.signedData, signedData));
    }

    private SignerInfo buildSignerInfo(SignerEntry entry) throws PkixException {
      AlgorithmIdentifier sigAlg = entry.signer.getAlgorithmIdentifier();
      AlgorithmIdentifier signerInfoSigAlg = CmsCrypto.signerInfoSignatureAlgorithm(sigAlg);

      List<Attribute> attrs = new ArrayList<>();
      if (entry.signedAttributes != null) {
        for (Attribute attr : entry.signedAttributes) {
          attrs.add(attr);
        }
      }

      if (!hasAttribute(attrs, CmsOIDs.contentType)) {
        attrs.add(Attribute.ofCmsContentType(contentType));
      }

      if (!hasAttribute(attrs, CmsOIDs.signingTime)) {
        attrs.add(Attribute.ofSigningTime(Instant.now()));
      }

      if (!hasAttribute(attrs, CmsOIDs.messageDigest)) {
        attrs.add(Attribute.ofMessageDigest(CmsCrypto.digest(entry.digestAlgorithm,
            content == null ? new byte[0] : content)));
      }

      if (!hasAttribute(attrs, CmsOIDs.cmsAlgorithmProtect)) {
        attrs.add(Attribute.ofCmsAlgorithmProtection(
            CMSAlgorithmProtection.ofSignatureAlgorithm(entry.digestAlgorithm, signerInfoSigAlg)));
      }

      Attributes signedAttrs = new Attributes(attrs);
      byte[] signature;
      try {
        signature = entry.signer.atomicSign(signedAttrs.getEncoded());
      } catch (SignatureException e) {
        throw new PkixException("could not sign: " + e.getMessage(), e);
      }

      SignerIdentifier sid = SignerIdentifier.ofIssuerAndSerialNumber(
          new IssuerAndSerialNumber(entry.cert));
      return new SignerInfo(sid, entry.digestAlgorithm, signedAttrs, signerInfoSigAlg,
          new Asn1OctetString(signature), entry.unsignedAttributes);
    }

    private static boolean hasAttribute(List<Attribute> attrs, Asn1Oid type) {
      for (Attribute attr : attrs) {
        if (attr.getAttrType().equals(type)) {
          return true;
        }
      }
      return false;
    }

  }
}
