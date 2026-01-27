// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.api.mgmt;

import org.xipki.ca.api.mgmt.entry.CaEntry;
import org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry;
import org.xipki.ca.api.mgmt.entry.CertprofileEntry;
import org.xipki.ca.api.mgmt.entry.ChangeCaEntry;
import org.xipki.ca.api.mgmt.entry.KeypairGenEntry;
import org.xipki.ca.api.mgmt.entry.PublisherEntry;
import org.xipki.ca.api.mgmt.entry.RequestorEntry;
import org.xipki.ca.api.mgmt.entry.SignerEntry;
import org.xipki.security.CertRevocationInfo;
import org.xipki.security.CrlReason;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.CodecException;
import org.xipki.util.codec.json.JsonMap;

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;

/**
 * CA Management request via the REST API.
 *
 * @author Lijun Liao (xipki)
 */

public abstract class MgmtRequest extends MgmtMessage {

  public static class AddOrChangeDbSchema extends MgmtRequest {

    private final String name;
    private final String value;

    public AddOrChangeDbSchema(String name, String value) {
      this.name = Args.notBlank(name, "name");
      this.value = value;
    }

    public String getName() {
      return name;
    }

    public String getValue() {
      return value;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("name", name);
      ret.put("value", value);
      return ret;
    }

    public static AddOrChangeDbSchema parse(JsonMap json)
        throws CodecException {
      return new AddOrChangeDbSchema(json.getString("name"),
          json.getString("value"));
    }

  }

  public static class AddCaAlias extends CaNameRequest {

    private final String aliasName;

    public String getAliasName() {
      return aliasName;
    }

    public AddCaAlias(String caName, String aliasName) {
      super(caName);
      this.aliasName = Args.notBlank(aliasName, "aliasName");
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      toJson(ret);
      ret.put("aliasName", aliasName);
      return ret;
    }

    public static AddCaAlias parse(JsonMap json) throws CodecException {
      return new AddCaAlias(
          json.getNnString("caName"),
          json.getNnString("aliasName"));
    }

  } // class AddCaAlias

  public static class AddCa extends MgmtRequest {

    private final CaEntry caEntry;

    public AddCa(CaEntry caEntry) {
      this.caEntry = Args.notNull(caEntry, "caEntry");
    }

    public CaEntry getCaEntry() {
      return caEntry;
    }

    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("caEntry", caEntry.toCodec());
      return ret;
    }

    public static AddCa parse(JsonMap json) throws CodecException {
      return new AddCa(CaEntry.parse(json.getNnMap("caEntry")));
    }

  } // class AddCa

  public static class AddCertprofile extends MgmtRequest {

    private final CertprofileEntry certprofileEntry;

    public AddCertprofile(CertprofileEntry certprofileEntry) {
      this.certprofileEntry = Args.notNull(certprofileEntry,
          "certprofileEntry");
    }

    public CertprofileEntry getCertprofileEntry() {
      return certprofileEntry;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("certprofileEntry", certprofileEntry.toCodec());
      return ret;
    }

    public static AddCertprofile parse(JsonMap json) throws CodecException {
      return new AddCertprofile(CertprofileEntry.parse(
          json.getNnMap("certprofileEntry")));
    }

  } // class AddCertprofile

  public static class AddCertprofileToCa extends CaNameRequest {

    private final String profileName;

    public AddCertprofileToCa(String caName, String profileName) {
      super(caName);
      this.profileName = Args.notBlank(profileName, "profileName");
    }

    public String getProfileName() {
      return profileName;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      toJson(ret);
      ret.put("profileName", profileName);
      return ret;
    }

    public static AddCertprofileToCa parse(JsonMap json)
        throws CodecException {
      return new AddCertprofileToCa(
          json.getNnString("caName"),
          json.getNnString("profileName"));
    }

  } // class AddCertprofileToCa

  public static class AddKeypairGen extends MgmtRequest {

    private final KeypairGenEntry entry;

    public AddKeypairGen(KeypairGenEntry entry) {
      this.entry = Args.notNull(entry, "entry");
    }

    public KeypairGenEntry getEntry() {
      return entry;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("entry", entry.toCodec());
      return ret;
    }

    public static AddKeypairGen parse(JsonMap json) throws CodecException {
      return new AddKeypairGen(KeypairGenEntry.parse(
          json.getNnMap("entry")));
    }

  } // class AddKeypairGen

  public static class AddPublisher extends MgmtRequest {

    private final PublisherEntry publisherEntry;

    public AddPublisher(PublisherEntry publisherEntry) {
      this.publisherEntry = Args.notNull(publisherEntry, "publisherEntry");
    }

    public PublisherEntry getPublisherEntry() {
      return publisherEntry;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("publisherEntry", publisherEntry.toCodec());
      return ret;
    }

    public static AddPublisher parse(JsonMap json) throws CodecException {
      return new AddPublisher(PublisherEntry.parse(
          json.getNnMap("publisherEntry")));
    }

  } // class AddPublisher

  public static class AddPublisherToCa extends CaNameRequest {

    private final String publisherName;

    public AddPublisherToCa(String caName, String publisherName) {
      super(caName);
      this.publisherName = Args.notBlank(publisherName, "publisherName");
    }

    public String getPublisherName() {
      return publisherName;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("publisherName", publisherName);
      return ret;
    }

    public static AddPublisherToCa parse(JsonMap json) throws CodecException {
      return new AddPublisherToCa(
          json.getNnString("caName"),
          json.getNnString("publisherName"));
    }
  } // class AddPublisherToCa

  public static class AddRequestor extends MgmtRequest {

    private final RequestorEntry requestorEntry;

    public AddRequestor(RequestorEntry requestorEntry) {
      this.requestorEntry = Args.notNull(requestorEntry, "requestorEntry");
    }

    public RequestorEntry getRequestorEntry() {
      return requestorEntry;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("requestorEntry", requestorEntry.toCodec());
      return ret;
    }

    public static AddRequestor parse(JsonMap json) throws CodecException {
      return new AddRequestor(RequestorEntry.parse(
          json.getNnMap("requestorEntry")));
    }

  } // class AddRequestor

  public static class AddRequestorToCa extends CaNameRequest {

    private final CaHasRequestorEntry requestor;

    public AddRequestorToCa(String caName, CaHasRequestorEntry requestor) {
      super(caName);
      this.requestor = Args.notNull(requestor, "requestor");
    }

    public CaHasRequestorEntry getRequestor() {
      return requestor;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("requestor", requestor.toCodec());
      return ret;
    }

    public static AddRequestorToCa parse(JsonMap json) throws CodecException {
      return new AddRequestorToCa(json.getNnString("caName"),
          CaHasRequestorEntry.parse(json.getNnMap("requestor")));
    }

  } // class AddRequestorToCa

  public static class AddSigner extends MgmtRequest {

    private final SignerEntry signerEntry;

    public AddSigner(SignerEntry signerEntry) {
      this.signerEntry = Args.notNull(signerEntry, "signerEntry");
    }

    public SignerEntry getSignerEntry() {
      return signerEntry;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("signerEntry", signerEntry.toCodec());
      return ret;
    }

    public static AddSigner parse(JsonMap json) throws CodecException {
      return new AddSigner(SignerEntry.parse(
          json.getNnMap("signerEntry")));
    }

  } // class AddSigner

  public abstract static class CaNameRequest extends MgmtRequest {

    protected String caName;

    protected CaNameRequest(String caName) {
      this.caName = Args.notBlank(caName, "caName");
    }

    public String getCaName() {
      return caName;
    }

    protected void toJson(JsonMap json) {
      json.put("caName", caName);
    }

  } // class CaNameRequest

  public static class ChangeCa extends MgmtRequest {

    private final ChangeCaEntry changeCaEntry;

    public ChangeCa(ChangeCaEntry changeCaEntry) {
      this.changeCaEntry = Args.notNull(changeCaEntry, "changeCaEntry");
    }

    public ChangeCaEntry getChangeCaEntry() {
      return changeCaEntry;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("changeCaEntry", changeCaEntry.toCodec());
      return ret;
    }

    public static ChangeCa parse(JsonMap json) throws CodecException {
      return new ChangeCa(ChangeCaEntry.parse(
          json.getNnMap("changeCaEntry")));
    }

  } // class ChangeCa

  public static class ChangeSigner extends MgmtRequest {

    private final String name;

    private String type;

    private String conf;

    private String base64Cert;

    public String getName() {
      return name;
    }

    public ChangeSigner(String name) {
      this.name = Args.notBlank(name, "name");
    }

    public String getType() {
      return type;
    }

    public void setType(String type) {
      this.type = type;
    }

    public String getConf() {
      return conf;
    }

    public void setConf(String conf) {
      this.conf = conf;
    }

    public String getBase64Cert() {
      return base64Cert;
    }

    public void setBase64Cert(String base64Cert) {
      this.base64Cert = base64Cert;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("name", name);
      ret.put("type", type);
      ret.put("conf", conf);
      ret.put("base64Cert", base64Cert);
      return ret;
    }

    public static ChangeSigner parse(JsonMap json) throws CodecException {
      ChangeSigner ret = new ChangeSigner(json.getNnString("name"));
      ret.setType(json.getString("type"));
      ret.setConf(json.getString("conf"));
      ret.setBase64Cert(json.getString("base64Cert"));
      return ret;
    }

  } // class ChangeSigner

  public static class ChangeTypeConfEntity extends MgmtRequest {

    private final String name;

    private final String type;

    private final String conf;

    public ChangeTypeConfEntity(String name, String type, String conf) {
      this.name = Args.notNull(name, "name");
      this.type = type;
      this.conf = conf;
    }

    public String getName() {
      return name;
    }

    public String getType() {
      return type;
    }

    public String getConf() {
      return conf;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("name", name);
      ret.put("type", type);
      ret.put("conf", conf);
      return ret;
    }

    public static ChangeTypeConfEntity parse(JsonMap json)
        throws CodecException {
      return new ChangeTypeConfEntity(json.getNnString("name"),
          json.getString("type"), json.getString("conf"));
    }

  } // class ChangeTypeConfEntity

  public static class ExportConf extends MgmtRequest {

    private final List<String> caNames;

    public ExportConf(List<String> caNames) {
      this.caNames = caNames;
    }

    public List<String> getCaNames() {
      return caNames;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.putStrings("caNames", caNames);
      return ret;
    }

    public static ExportConf parse(JsonMap json) throws CodecException {
      return new ExportConf(json.getStringList("caNames"));
    }

  } // class ExportConf

  private abstract static class AbstractGenerateCert extends CaNameRequest {

    private final String profileName;

    private final Instant notBefore;

    private final Instant notAfter;

    protected AbstractGenerateCert(
        String caName, String profileName,
        Instant notBefore, Instant notAfter) {
      super(caName);
      this.profileName = Args.notBlank(profileName, "profileName");
      this.notBefore = notBefore;
      this.notAfter = notAfter;
    }

    public String getProfileName() {
      return profileName;
    }

    public Instant getNotBefore() {
      return notBefore;
    }

    public Instant getNotAfter() {
      return notAfter;
    }

    protected void toJson(JsonMap json) {
      super.toJson(json);
      json.put("profileName", profileName);
      json.put("notBefore", notBefore);
      json.put("notAfter", notAfter);
    }

  } // class GenerateCertificate

  public static class GenerateCert extends AbstractGenerateCert {

    private final byte[] encodedCsr;

    public GenerateCert(
        String caName, String profileName, Instant notBefore,
        Instant notAfter, byte[] encodedCsr) {
      super(caName, profileName, notBefore, notAfter);
      this.encodedCsr = Args.notNull(encodedCsr, "encodedCsr");
    }

    public byte[] getEncodedCsr() {
      return encodedCsr;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("encodedCsr", encodedCsr);
      return ret;
    }

    public static GenerateCert parse(JsonMap json) throws CodecException {
      return new GenerateCert(json.getNnString("caName"),
          json.getNnString("profileName"),
          json.getInstant("notBefore"),
          json.getInstant("notAfter"),
          json.getNnBytes("encodedCsr"));
    }

  } // class GenerateCertificate

  public static class GenerateKeyCert extends AbstractGenerateCert {

    private final String subject;

    public GenerateKeyCert(
        String caName, String profileName, Instant notBefore,
        Instant notAfter, String subject) {
      super(caName, profileName, notBefore, notAfter);
      this.subject = Args.notBlank(subject, "subject");
    }

    public String getSubject() {
      return subject;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("subject", subject);
      return ret;
    }

    public static GenerateKeyCert parse(JsonMap json) throws CodecException {
      return new GenerateKeyCert(json.getNnString("caName"),
          json.getNnString("profileName"),
          json.getInstant("notBefore"),
          json.getInstant("notAfter"),
          json.getNnString("subject"));
    }
  } // class GenerateKeyCert

  public static class GenerateCrossCertificate extends CaNameRequest {

    private final String profileName;

    private final byte[] encodedCsr;

    private final byte[] encodedTargetCert;

    private final Instant notBefore;

    private final Instant notAfter;

    public GenerateCrossCertificate(
        String caName, String profileName, byte[] encodedCsr,
        byte[] encodedTargetCert, Instant notBefore, Instant notAfter) {
      super(caName);
      this.profileName = Args.notBlank(profileName, "profileName");
      this.encodedCsr = encodedCsr;
      this.encodedTargetCert = encodedTargetCert;
      this.notBefore = notBefore;
      this.notAfter = notAfter;
    }

    public String getProfileName() {
      return profileName;
    }

    public byte[] getEncodedCsr() {
      return encodedCsr;
    }

    public byte[] getEncodedTargetCert() {
      return encodedTargetCert;
    }

    public Instant getNotBefore() {
      return notBefore;
    }

    public Instant getNotAfter() {
      return notAfter;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);

      ret.put("profileName", profileName);
      ret.put("encodedCsr", encodedCsr);
      ret.put("encodedTargetCert", encodedTargetCert);
      ret.put("notBefore", notBefore);
      ret.put("notAfter",  notAfter);
      return ret;
    }

    public static GenerateCrossCertificate parse(JsonMap json)
        throws CodecException {
      return new GenerateCrossCertificate(
          json.getNnString("caName"),
          json.getNnString("profileName"),
          json.getBytes("encodedCsr"),
          json.getBytes("encodedTargetCert"),
          json.getInstant("notBefore"),
          json.getInstant("notAfter"));
    }

  } // class GenerateCrossCertificate

  public static class GenerateRootCa extends MgmtRequest {

    private final CaEntry caEntry;

    private final String profileName;

    private final String subject;

    private String serialNumber;

    private Instant notBefore;

    private Instant notAfter;

    public GenerateRootCa(CaEntry caEntry, String profileName, String subject) {
      this.caEntry = Args.notNull(caEntry, "caEntry");
      this.profileName = Args.notBlank(profileName, "profileName");
      this.subject = Args.notBlank(subject, "subject");
    }

    public CaEntry getCaEntry() {
      return caEntry;
    }

    public String getProfileName() {
      return profileName;
    }

    public String getSubject() {
      return subject;
    }

    public String getSerialNumber() {
      return serialNumber;
    }

    public void setSerialNumber(String serialNumber) {
      this.serialNumber = serialNumber;
    }

    public Instant getNotBefore() {
      return notBefore;
    }

    public void setNotBefore(Instant notBefore) {
      this.notBefore = notBefore;
    }

    public Instant getNotAfter() {
      return notAfter;
    }

    public void setNotAfter(Instant notAfter) {
      this.notAfter = notAfter;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("caEntry", caEntry.toCodec());
      ret.put("profileName", profileName);
      ret.put("subject", subject);
      ret.put("serialNumber", serialNumber);
      ret.put("notBefore", notBefore);
      ret.put("notAfter",  notAfter);
      return ret;
    }

    public static GenerateRootCa parse(JsonMap json) throws CodecException {
      GenerateRootCa ret = new GenerateRootCa(
          CaEntry.parse(json.getNnMap("caEntry")),
          json.getNnString("profileName"),
          json.getNnString("subject"));

      ret.setSerialNumber(json.getString("serialNumber"));
      ret.setNotBefore(json.getInstant("notBefore"));
      ret.setNotAfter(json.getInstant("notAfter"));
      return ret;
    }

  } // class GenerateRootCa

  public static class GetCert extends MgmtRequest {

    /**
     * CA name. Either caName or issuerDn must be set.
     */
    private final String caName;

    /**
     * Issuer DN. Either caName or issuerDn must be set.
     */
    private final byte[] encodedIssuerDn;

    private final BigInteger serialNumber;

    public String getCaName() {
      return caName;
    }

    public byte[] getEncodedIssuerDn() {
      return encodedIssuerDn;
    }

    public GetCert(String caName, BigInteger serialNumber) {
      this.caName = Args.notBlank(caName, "caName");
      this.encodedIssuerDn = null;
      this.serialNumber = serialNumber;
    }

    public GetCert(byte[] encodedIssuerDn, BigInteger serialNumber) {
      this.caName = null;
      this.encodedIssuerDn = Args.notNull(encodedIssuerDn, "encodedIssuerDn");
      this.serialNumber = serialNumber;
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("caName", caName);
      ret.put("encodedIssuerDn", encodedIssuerDn);
      ret.put("serialNumber", serialNumber);
      return ret;
    }

    public static GetCert parse(JsonMap json) throws CodecException {
      String caName = json.getString("caName");
      BigInteger serialNumber = json.getBigInteger("serialNumber");

      if (caName != null) {
        return new GetCert(caName, serialNumber);
      } else {
        return new GetCert(json.getNnBytes("encodedIssuerDn"), serialNumber);
      }
    }

  } // class GetCert

  public static class GetCrl extends CaNameRequest {

    private final BigInteger crlNumber;

    public GetCrl(String caName, BigInteger crlNumber) {
      super(caName);
      this.crlNumber = crlNumber;
    }

    public BigInteger getCrlNumber() {
      return crlNumber;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("crlNumber", crlNumber);
      return ret;
    }

    public static GetCrl parse(JsonMap json) throws CodecException {
      return new GetCrl(json.getNnString("caName"),
          json.getBigInteger("crlNumber"));
    }

  } // class GetCrl

  public static class ListCertificates extends CaNameRequest {

    private byte[] encodedSubjectDnPattern;

    private Instant validFrom;

    private Instant validTo;

    private CertListOrderBy orderBy;

    private int numEntries;

    public ListCertificates(String caName) {
      super(caName);
    }

    public byte[] getEncodedSubjectDnPattern() {
      return encodedSubjectDnPattern;
    }

    public void setEncodedSubjectDnPattern(byte[] encodedSubjectDnPattern) {
      this.encodedSubjectDnPattern = encodedSubjectDnPattern;
    }

    public Instant getValidFrom() {
      return validFrom;
    }

    public void setValidFrom(Instant validFrom) {
      this.validFrom = validFrom;
    }

    public Instant getValidTo() {
      return validTo;
    }

    public void setValidTo(Instant validTo) {
      this.validTo = validTo;
    }

    public CertListOrderBy getOrderBy() {
      return orderBy;
    }

    public void setOrderBy(CertListOrderBy orderBy) {
      this.orderBy = orderBy;
    }

    public int getNumEntries() {
      return numEntries;
    }

    public void setNumEntries(int numEntries) {
      this.numEntries = numEntries;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("encodedSubjectDnPattern", encodedSubjectDnPattern);
      ret.put("validFrom", validFrom);
      ret.put("validTo", validTo);
      if (orderBy != null) {
        ret.put("orderBy", orderBy.getText());
      }
      ret.put("numEntries", numEntries);
      return ret;
    }

    public static ListCertificates parse(JsonMap json) throws CodecException {
      ListCertificates ret = new ListCertificates(
          json.getNnString("caName"));
      ret.setEncodedSubjectDnPattern(json.getBytes("encodedSubjectDnPattern"));
      ret.setValidFrom(json.getInstant("validFrom"));
      ret.setValidTo(json.getInstant("validTo"));
      ret.setNumEntries(json.getNnInt("numEntries"));
      String str = json.getString("orderBy");
      if (str != null) {
        ret.setOrderBy(CertListOrderBy.forValue(str));
      }
      return ret;
    }

  } // class ListCertificates

  public static class LoadConf extends MgmtRequest {

    private final byte[] confBytes;

    public LoadConf(byte[] confBytes) {
      this.confBytes = Args.notNull(confBytes, "confBytes");
    }

    public byte[] getConfBytes() {
      return confBytes;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("confBytes", confBytes);
      return ret;
    }

    public static LoadConf parse(JsonMap json) throws CodecException {
      return new LoadConf(json.getNnBytes("confBytes"));
    }

  } // class LoadConf

  public static class Name extends MgmtRequest {

    private final String name;

    public Name(String name) {
      this.name = name;
    }

    public String getName() {
      return name;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("name", name);
      return ret;
    }

    public static Name parse(JsonMap json) throws CodecException {
      return new Name(json.getNnString("name"));
    }

  } // class Name

  public static class RemoveCertificate extends CaNameRequest {

    private final BigInteger serialNumber;

    public RemoveCertificate(String caName, BigInteger serialNumber) {
      super(caName);
      this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("serialNumber", serialNumber);
      return ret;
    }

    public static RemoveCertificate parse(JsonMap json) throws CodecException {
      return new RemoveCertificate(
          json.getNnString("caName"),
          json.getNnBigInteger("serialNumber"));
    }
  } // class RemoveCertificate

  public static class RemoveEntityFromCa extends CaNameRequest {

    private final String entityName;

    public String getEntityName() {
      return entityName;
    }

    public RemoveEntityFromCa(String caName, String entityName) {
      super(caName);
      this.entityName = Args.notBlank(entityName, "entityName");
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("entityName", entityName);
      return ret;
    }

    public static RemoveEntityFromCa parse(JsonMap json)
        throws CodecException {
      return new RemoveEntityFromCa(json.getNnString("caName"),
          json.getNnString("entityName"));
    }

  } // class RemoveEntityFromCa

  public static class RepublishCertificates extends CaNameRequest {

    private final List<String> publisherNames;

    private final int numThreads;

    public RepublishCertificates(
        String caName, List<String> publisherNames, int numThreads) {
      super(caName);
      this.publisherNames = publisherNames;
      this.numThreads = Args.positive(numThreads, "numThreads");
    }

    public List<String> getPublisherNames() {
      return publisherNames;
    }

    public int getNumThreads() {
      return numThreads;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("numThreads", numThreads);
      ret.putStrings("publisherNames", publisherNames);
      return ret;
    }

    public static RepublishCertificates parse(JsonMap json)
        throws CodecException {
      return new RepublishCertificates(json.getNnString("caName"),
          json.getStringList("publisherNames"),
          json.getInt("numThreads", 1));
    }

  } // class RepublishCertificates

  public static class RevokeCa extends CaNameRequest {

    private final CertRevocationInfo revocationInfo;

    public RevokeCa(String caName, CertRevocationInfo revocationInfo) {
      super(caName);
      this.revocationInfo = revocationInfo;
    }

    public CertRevocationInfo getRevocationInfo() {
      return revocationInfo;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("revocationInfo", revocationInfo.toCodec());
      return ret;
    }

    public static RevokeCa parse(JsonMap json) throws CodecException {
      CertRevocationInfo revInfo = null;
      JsonMap map = json.getMap("revocationInfo");
      if (map != null) {
        revInfo = CertRevocationInfo.parse(map);
      }
      return new RevokeCa(json.getNnString("caName"), revInfo);
    }

  } // class RevokeCa

  public static class RevokeCertificate extends CaNameRequest {

    private final BigInteger serialNumber;

    private final CrlReason reason;

    private final Instant invalidityTime;

    public RevokeCertificate(String caName, BigInteger serialNumber,
                             CrlReason reason, Instant invalidityTime) {
      super(caName);
      this.serialNumber = Args.notNull(serialNumber, "serialNumber");
      this.reason = reason;
      this.invalidityTime = invalidityTime;
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    public CrlReason getReason() {
      return reason;
    }

    public Instant getInvalidityTime() {
      return invalidityTime;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("serialNumber", serialNumber);
      ret.putEnum("reason", reason);
      ret.put("invalidityTime", invalidityTime);
      return ret;
    }

    public static RevokeCertificate parse(JsonMap json) throws CodecException {
      String str = json.getString("reason");
      CrlReason reason = null;
      if (str != null) {
        reason = CrlReason.forNameOrText(str);
      }

      return new RevokeCertificate(json.getNnString("caName"),
          json.getNnBigInteger("serialNumber"), reason,
          json.getInstant("invalidityTime"));
    }

  } // class RevokeCertificate

  public static class UnsuspendCertificate extends CaNameRequest {

    private final BigInteger serialNumber;

    public UnsuspendCertificate(String caName, BigInteger serialNumber) {
      super(caName);
      this.serialNumber = Args.notNull(serialNumber, "serialNumber");
    }

    public BigInteger getSerialNumber() {
      return serialNumber;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      super.toJson(ret);
      ret.put("serialNumber", serialNumber);
      return ret;
    }

    public static UnsuspendCertificate parse(JsonMap json)
        throws CodecException {
      return new UnsuspendCertificate(
          json.getNnString("caName"),
          json.getNnBigInteger("serialNumber"));
    }

  } // class UnrevokeCertificate

  public static class TokenInfoP11 extends MgmtRequest {

    private final boolean verbose;

    private final String moduleName;

    private final Integer slotIndex;

    public TokenInfoP11(String moduleName, Integer slotIndex, boolean verbose) {
      this.moduleName = moduleName;
      this.slotIndex = slotIndex;
      this.verbose = verbose;
    }

    public boolean isVerbose() {
      return verbose;
    }

    public String getModuleName() {
      return moduleName;
    }

    public Integer getSlotIndex() {
      return slotIndex;
    }

    @Override
    public JsonMap toCodec() {
      JsonMap ret = new JsonMap();
      ret.put("verbose", verbose);
      ret.put("moduleName", moduleName);
      ret.put("slotIndex", slotIndex);
      return ret;
    }

    public static TokenInfoP11 parse(JsonMap json) throws CodecException {
      return new TokenInfoP11(
          json.getString("moduleName"),
          json.getInt("slotIndex"),
          json.getBool("verbose", false));
    }
  }

}
