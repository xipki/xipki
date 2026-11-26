// License Apache License 2.0

package org.xipki.mgmt.web.ca;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.xipki.codec.json.JsonList;
import org.xipki.codec.json.JsonMap;
import org.xipki.codec.util.ConfPairs;
import org.xipki.mgmt.web.ca.CaDomain.BaseCaInfo;
import org.xipki.mgmt.web.ca.CaDomain.CaStatus;
import org.xipki.mgmt.web.ca.CaDomain.CaUris;
import org.xipki.mgmt.web.ca.CaDomain.CaMgmtException;
import org.xipki.mgmt.web.ca.CaDomain.CaProfileEntry;
import org.xipki.mgmt.web.ca.CaDomain.CaEntry;
import org.xipki.mgmt.web.ca.CaDomain.CaHasRequestorEntry;
import org.xipki.mgmt.web.ca.CaDomain.CaSystemStatus;
import org.xipki.mgmt.web.ca.CaDomain.CertListInfo;
import org.xipki.mgmt.web.ca.CaDomain.CertListOrderBy;
import org.xipki.mgmt.web.ca.CaDomain.CertprofileEntry;
import org.xipki.mgmt.web.ca.CaDomain.CertRevocationInfo;
import org.xipki.mgmt.web.ca.CaDomain.CertWithDbId;
import org.xipki.mgmt.web.ca.CaDomain.CertWithRevocationInfo;
import org.xipki.mgmt.web.ca.CaDomain.ChangeCaEntry;
import org.xipki.mgmt.web.ca.CaDomain.CrlControl;
import org.xipki.mgmt.web.ca.CaDomain.CrlReason;
import org.xipki.mgmt.web.ca.CaDomain.CtlogControl;
import org.xipki.mgmt.web.ca.CaDomain.KeypairGenEntry;
import org.xipki.mgmt.web.ca.CaDomain.NameId;
import org.xipki.mgmt.web.ca.CaDomain.Permissions;
import org.xipki.mgmt.web.ca.CaDomain.PublisherEntry;
import org.xipki.mgmt.web.ca.CaDomain.RequestorEntry;
import org.xipki.mgmt.web.ca.CaDomain.RevokeSuspendedControl;
import org.xipki.mgmt.web.ca.CaDomain.SignerEntry;
import org.xipki.mgmt.web.ca.CaDomain.ValidityMode;
import org.xipki.util.conf.Validity;

/**
 * Bridge from the Console management boundary to XiPKI's official client.
 */
public final class OfficialCaMgmtClientAdapter implements CaManager {
  private final org.xipki.ca.mgmt.client.CaMgmtClient official;

  /** Creates the authenticated official management client used by every Console CA operation. */
  public OfficialCaMgmtClientAdapter(
      String address, Path keyStore, char[] password, Path trustAnchors) throws Exception {
    this(OfficialCaMgmtClientFactory.create(address, keyStore, password, trustAnchors));
  }

  /** Injects the external client for adapter contract tests without constructing a network peer. */
  OfficialCaMgmtClientAdapter(org.xipki.ca.mgmt.client.CaMgmtClient official) {
    this.official = Objects.requireNonNull(official);
  }

  /** Reads aggregate CA runtime state through the official XiPKI client. */
  @Override
  public CaSystemStatus getCaSystemStatus() throws CaMgmtException {
    try {
      return CaSystemStatus.valueOf(official.getCaSystemStatus().name());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Lists every configured CA name through the official XiPKI client. */
  @Override
  public Set<String> getCaNames() throws CaMgmtException {
    try {
      return official.getCaNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Lists running CA names through the official XiPKI client. */
  @Override
  public Set<String> getSuccessfulCaNames() throws CaMgmtException {
    try {
      return official.getSuccessfulCaNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Lists CA names that failed to start through the official XiPKI client. */
  @Override
  public Set<String> getFailedCaNames() throws CaMgmtException {
    try {
      return official.getFailedCaNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Lists inactive CA names through the official XiPKI client. */
  @Override
  public Set<String> getInactiveCaNames() throws CaMgmtException {
    try {
      return official.getInactiveCaNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Reads a CA definition through the official client and maps its supported codec contract. */
  @Override
  public CaEntry getCa(String caName) throws CaMgmtException {
    try {
      var value = official.getCa(caName);
      if (value == null) {
        return null;
      }
      // The XiPKI codec normalizes integer values to JSON longs at its serialization boundary.
      var encoded = org.xipki.codec.json.JsonBuilder.toJson(value.toCodec());
      var normalized = org.xipki.codec.json.JsonParser.parseMap(encoded, false);
      return caEntry(normalized);
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    } catch (Exception ex) {
      throw new CaMgmtException("could not convert CA entry", ex);
    }
  }

  /** Adds one CA through the official client after a lossless domain-object conversion. */
  @Override
  public void addCa(CaEntry entry) throws CaMgmtException {
    try {
      official.addCa(officialCaEntry(entry));
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    } catch (Exception ex) {
      throw new CaMgmtException("could not convert CA entry", ex);
    }
  }

  /** Changes one CA through the official client while preserving nullable patch semantics. */
  @Override
  public void changeCa(ChangeCaEntry entry) throws CaMgmtException {
    try {
      official.changeCa(officialChangeCaEntry(entry));
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    } catch (Exception ex) {
      throw new CaMgmtException("could not convert CA change", ex);
    }
  }

  /** Removes one CA through the official XiPKI client. */
  @Override
  public void removeCa(String caName) throws CaMgmtException {
    mutate(() -> official.removeCa(caName));
  }

  /** Revokes one CA without dropping its recorded revocation or invalidity time. */
  @Override
  public void revokeCa(String caName, CertRevocationInfo revocationInfo)
      throws CaMgmtException {
    var officialRevocation =
        new org.xipki.pkix.cert.CertRevocationInfo(
            org.xipki.pkix.cert.CrlReason.valueOf(revocationInfo.reason().name()),
            revocationInfo.revocationTime(),
            revocationInfo.invalidityTime());
    mutate(() -> official.revokeCa(caName, officialRevocation));
  }

  /** Restores a revoked CA through the official XiPKI client. */
  @Override
  public void unrevokeCa(String caName) throws CaMgmtException {
    mutate(() -> official.unrevokeCa(caName));
  }

  /** Lists certificate profiles associated with one CA through the official client. */
  @Override
  public Set<CaProfileEntry> getCertprofilesForCa(String caName) throws CaMgmtException {
    try {
      var source = official.getCertprofilesForCa(caName);
      var result = new LinkedHashSet<CaProfileEntry>(source.size());
      for (var entry : source) {
        result.add(new CaProfileEntry(entry.profileName(), entry.profileAliases()));
      }
      return result;
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Associates a certificate profile and its aliases with one CA. */
  @Override
  public void addCertprofileToCa(String profileNameAliases, String caName)
      throws CaMgmtException {
    mutate(() -> official.addCertprofileToCa(profileNameAliases, caName));
  }

  /** Removes a certificate profile association from one CA. */
  @Override
  public void removeCertprofileFromCa(String profileName, String caName)
      throws CaMgmtException {
    mutate(() -> official.removeCertprofileFromCa(profileName, caName));
  }

  /** Lists certificate profile names through the official XiPKI client. */
  @Override
  public Set<String> getCertprofileNames() throws CaMgmtException {
    try {
      return official.getCertprofileNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Reads one certificate profile through the official client. */
  @Override
  public CertprofileEntry getCertprofile(String profileName) throws CaMgmtException {
    try {
      var value = official.getCertprofile(profileName);
      return value == null
          ? null
          : new CertprofileEntry(
              nameId(value.ident()), value.type(), value.conf());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Adds one certificate profile through the official client. */
  @Override
  public void addCertprofile(CertprofileEntry entry) throws CaMgmtException {
    var officialEntry =
        new org.xipki.ca.api.mgmt.entry.CertprofileEntry(
            officialNameId(entry.getIdent()), entry.getType(), entry.getConf());
    mutate(() -> official.addCertprofile(officialEntry));
  }

  /** Changes one certificate profile through the official client. */
  @Override
  public void changeCertprofile(String name, String type, String conf) throws CaMgmtException {
    mutate(() -> official.changeCertprofile(name, type, conf));
  }

  /** Removes one certificate profile through the official client. */
  @Override
  public void removeCertprofile(String profileName) throws CaMgmtException {
    mutate(() -> official.removeCertprofile(profileName));
  }

  /** Lists key-pair generator names through the official XiPKI client. */
  @Override
  public Set<String> getKeypairGenNames() throws CaMgmtException {
    try {
      return official.getKeypairGenNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Reads one key-pair generator through the official client. */
  @Override
  public KeypairGenEntry getKeypairGen(String name) throws CaMgmtException {
    try {
      var value = official.getKeypairGen(name);
      return value == null
          ? null
          : new KeypairGenEntry(value.name(), value.type(), value.conf());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Adds one key-pair generator through the official client. */
  @Override
  public void addKeypairGen(KeypairGenEntry entry) throws CaMgmtException {
    var officialEntry =
        new org.xipki.ca.api.mgmt.entry.KeypairGenEntry(
            entry.getName(), entry.getType(), entry.getConf());
    mutate(() -> official.addKeypairGen(officialEntry));
  }

  /** Changes one key-pair generator through the official client. */
  @Override
  public void changeKeypairGen(String name, String type, String conf) throws CaMgmtException {
    mutate(() -> official.changeKeypairGen(name, type, conf));
  }

  /** Removes one key-pair generator through the official client. */
  @Override
  public void removeKeypairGen(String name) throws CaMgmtException {
    mutate(() -> official.removeKeypairGen(name));
  }

  /** Lists publisher names through the official XiPKI client. */
  @Override
  public Set<String> getPublisherNames() throws CaMgmtException {
    try {
      return official.getPublisherNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Reads one publisher through the official client. */
  @Override
  public PublisherEntry getPublisher(String publisherName) throws CaMgmtException {
    try {
      var value = official.getPublisher(publisherName);
      return value == null
          ? null
          : new PublisherEntry(nameId(value.ident()), value.type(), value.conf());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Adds one publisher through the official client. */
  @Override
  public void addPublisher(PublisherEntry entry) throws CaMgmtException {
    var officialEntry =
        new org.xipki.ca.api.mgmt.entry.PublisherEntry(
            officialNameId(entry.getIdent()), entry.getType(), entry.getConf());
    mutate(() -> official.addPublisher(officialEntry));
  }

  /** Changes one publisher through the official client. */
  @Override
  public void changePublisher(String name, String type, String conf) throws CaMgmtException {
    mutate(() -> official.changePublisher(name, type, conf));
  }

  /** Removes one publisher through the official client. */
  @Override
  public void removePublisher(String publisherName) throws CaMgmtException {
    mutate(() -> official.removePublisher(publisherName));
  }

  /** Lists requestor names through the official XiPKI client. */
  @Override
  public Set<String> getRequestorNames() throws CaMgmtException {
    try {
      return official.getRequestorNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Lists requestor authorizations for one CA without changing their permission scope. */
  @Override
  public Set<CaHasRequestorEntry> getRequestorsForCa(String caName) throws CaMgmtException {
    try {
      var source = official.getRequestorsForCa(caName);
      var result = new LinkedHashSet<CaHasRequestorEntry>(source.size());
      for (var entry : source) {
        result.add(
            new CaHasRequestorEntry(
                nameId(entry.requestorIdent()),
                new CaDomain.Permissions(entry.permissions().value()),
                entry.profiles()));
      }
      return result;
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Associates one requestor authorization with one CA through the official client. */
  @Override
  public void addRequestorToCa(CaHasRequestorEntry requestor, String caName)
      throws CaMgmtException {
    var profiles =
        requestor.getProfiles() == null
            ? List.<String>of()
            : new ArrayList<>(requestor.getProfiles());
    var officialRequestor =
        new org.xipki.ca.api.mgmt.entry.CaHasRequestorEntry(
            officialNameId(requestor.getRequestorIdent()),
            new org.xipki.ca.api.mgmt.Permissions(requestor.getPermissions().getValue()),
            profiles);
    mutate(() -> official.addRequestorToCa(officialRequestor, caName));
  }

  /** Removes one requestor authorization from one CA through the official client. */
  @Override
  public void removeRequestorFromCa(String requestorName, String caName)
      throws CaMgmtException {
    mutate(() -> official.removeRequestorFromCa(requestorName, caName));
  }

  /** Reads one requestor through the official client. */
  @Override
  public RequestorEntry getRequestor(String requestorName) throws CaMgmtException {
    try {
      var value = official.getRequestor(requestorName);
      return value == null
          ? null
          : new RequestorEntry(nameId(value.ident()), value.type(), value.conf());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Adds one requestor through the official client. */
  @Override
  public void addRequestor(RequestorEntry entry) throws CaMgmtException {
    var officialEntry =
        new org.xipki.ca.api.mgmt.entry.RequestorEntry(
            officialNameId(entry.getIdent()), entry.getType(), entry.getConf());
    mutate(() -> official.addRequestor(officialEntry));
  }

  /** Changes one requestor through the official client. */
  @Override
  public void changeRequestor(String name, String type, String conf) throws CaMgmtException {
    mutate(() -> official.changeRequestor(name, type, conf));
  }

  /** Removes one requestor through the official client. */
  @Override
  public void removeRequestor(String requestorName) throws CaMgmtException {
    mutate(() -> official.removeRequestor(requestorName));
  }

  /** Lists signer names through the official XiPKI client. */
  @Override
  public Set<String> getSignerNames() throws CaMgmtException {
    try {
      return official.getSignerNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Reads one signer through the official client. */
  @Override
  public SignerEntry getSigner(String signerName) throws CaMgmtException {
    try {
      var value = official.getSigner(signerName);
      return value == null
          ? null
          : new SignerEntry(value.name(), value.type(), value.conf(), value.base64Cert());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Adds one signer through the official client. */
  @Override
  public void addSigner(SignerEntry entry) throws CaMgmtException {
    var officialEntry =
        new org.xipki.ca.api.mgmt.entry.SignerEntry(
            entry.getName(), entry.getType(), entry.getConf(), entry.getBase64Cert());
    mutate(() -> official.addSigner(officialEntry));
  }

  /** Changes one signer through the official client. */
  @Override
  public void changeSigner(String name, String type, String conf, String base64Cert)
      throws CaMgmtException {
    mutate(() -> official.changeSigner(name, type, conf, base64Cert));
  }

  /** Removes one signer through the official client. */
  @Override
  public void removeSigner(String signerName) throws CaMgmtException {
    mutate(() -> official.removeSigner(signerName));
  }

  /** Lists every configured CA alias through the official XiPKI client. */
  @Override
  public Set<String> getCaAliasNames() throws CaMgmtException {
    try {
      return official.getCaAliasNames();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Lists aliases assigned to one CA through the official XiPKI client. */
  @Override
  public Set<String> getAliasesForCa(String caName) throws CaMgmtException {
    try {
      return official.getAliasesForCa(caName);
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Resolves one CA alias through the official XiPKI client. */
  @Override
  public String getCaNameForAlias(String aliasName) throws CaMgmtException {
    try {
      return official.getCaNameForAlias(aliasName);
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Lists publishers attached to one CA through the official XiPKI client. */
  @Override
  public Set<String> getPublisherNamesForCa(String caName) throws CaMgmtException {
    try {
      return official.getPublisherNamesForCa(caName);
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Associates one publisher with one CA through the official client. */
  @Override
  public void addPublisherToCa(String publisherName, String caName) throws CaMgmtException {
    mutate(() -> official.addPublisherToCa(publisherName, caName));
  }

  /** Removes one publisher association from one CA through the official client. */
  @Override
  public void removePublisherFromCa(String publisherName, String caName)
      throws CaMgmtException {
    mutate(() -> official.removePublisherFromCa(publisherName, caName));
  }

  /** Reads CA database schema properties through the official XiPKI client. */
  @Override
  public Map<String, String> getDbSchemas() throws CaMgmtException {
    try {
      return official.getDbSchemas();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Unlocks the CA system through the official XiPKI client without application-level retry. */
  @Override
  public void unlockCa() throws CaMgmtException {
    mutate(official::unlockCa);
  }

  /** Notifies the CA runtime of configuration changes through the official XiPKI client. */
  @Override
  public void notifyCaChange() throws CaMgmtException {
    mutate(official::notifyCaChange);
  }

  /** Restarts one CA through the official XiPKI client. */
  @Override
  public void restartCa(String caName) throws CaMgmtException {
    mutate(() -> official.restartCa(caName));
  }

  /** Restarts the complete CA system through the official XiPKI client. */
  @Override
  public void restartCaSystem() throws CaMgmtException {
    mutate(official::restartCaSystem);
  }

  /** Adds a CA alias through the official XiPKI client. */
  @Override
  public void addCaAlias(String aliasName, String caName) throws CaMgmtException {
    mutate(() -> official.addCaAlias(aliasName, caName));
  }

  /** Removes a CA alias through the official XiPKI client. */
  @Override
  public void removeCaAlias(String aliasName) throws CaMgmtException {
    mutate(() -> official.removeCaAlias(aliasName));
  }

  /** Adds a CA database schema property through the official XiPKI client. */
  @Override
  public void addDbSchema(String name, String value) throws CaMgmtException {
    mutate(() -> official.addDbSchema(name, value));
  }

  /** Changes a CA database schema property through the official XiPKI client. */
  @Override
  public void changeDbSchema(String name, String value) throws CaMgmtException {
    mutate(() -> official.changeDbSchema(name, value));
  }

  /** Removes a CA database schema property through the official XiPKI client. */
  @Override
  public void removeDbSchema(String name) throws CaMgmtException {
    mutate(() -> official.removeDbSchema(name));
  }

  /** Republishes certificates through the official XiPKI client. */
  @Override
  public void republishCertificates(String caName, List<String> publishers, int threads)
      throws CaMgmtException {
    mutate(() -> official.republishCertificates(caName, publishers, threads));
  }

  /** Generates a self-signed root CA through the official client and preserves its DER result. */
  @Override
  public Crypto.X509Cert generateRootCa(
      CaEntry caEntry,
      String certprofileName,
      String subject,
      String serialNumber,
      Instant notBefore,
      Instant notAfter)
      throws CaMgmtException {
    try {
      var certificate =
          official.generateRootCa(
              officialCaEntry(caEntry),
              certprofileName,
              subject,
              serialNumber,
              notBefore,
              notAfter);
      return certificate == null
          ? null
          : Crypto.X509Util.parseCert(certificate.getEncoded());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    } catch (Exception ex) {
      throw new CaMgmtException("could not generate root CA", ex);
    }
  }

  /** Generates a CRL through the official client and preserves the Console download contract. */
  @Override
  public Crypto.X509Crl generateCrlOnDemand(String caName) throws CaMgmtException {
    try {
      return crl(official.generateCrlOnDemand(caName));
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Reads a numbered CRL through the official client. */
  @Override
  public Crypto.X509Crl getCrl(String caName, long crlNumber) throws CaMgmtException {
    try {
      return crl(official.getCrl(caName, crlNumber));
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Reads the current CRL through the official client. */
  @Override
  public Crypto.X509Crl getCurrentCrl(String caName) throws CaMgmtException {
    try {
      return crl(official.getCurrentCrl(caName));
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Reads a CA certificate chain through the official client without changing DER bytes. */
  @Override
  public List<Crypto.X509Cert> getCaCerts(String caName) throws CaMgmtException {
    try {
      var source = official.getCaCerts(caName);
      if (source == null) {
        return null;
      }
      var result = new ArrayList<Crypto.X509Cert>(source.size());
      for (var certificate : source) {
        result.add(Crypto.X509Util.parseCert(certificate.getEncoded()));
      }
      return result;
    } catch (org.xipki.ca.api.mgmt.CaMgmtException | CertificateException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  }

  /**
   * Lists certificates through the official XiPKI client while preserving the Console DTO and the
   * XiPKI 7 empty-DN match-all workaround.
   */
  @Override
  public List<CertListInfo> listCertificates(
      String caName,
      X500Principal subjectPattern,
      Instant validFrom,
      Instant validTo,
      CertListOrderBy orderBy,
      int numEntries)
      throws CaMgmtException {
    try {
      byte[] encodedSubject =
          subjectPattern == null ? new X500Principal("").getEncoded() : subjectPattern.getEncoded();
      var officialSubject =
          org.xipki.asn1.x500.X500Name.fromEncoded(encodedSubject);
      var officialOrder =
          org.xipki.ca.api.mgmt.CertListOrderBy.valueOf(orderBy.name());
      var source =
          official.listCertificates(
              caName, officialSubject, validFrom, validTo, officialOrder, numEntries);
      var result = new ArrayList<CertListInfo>(source.size());
      for (var entry : source) {
        result.add(
            new CertListInfo(
                entry.serialNumber(),
                entry.subject(),
                entry.notBefore(),
                entry.notAfter(),
                revocation(entry.getRevocationInfo())));
      }
      return result;
    } catch (org.xipki.ca.api.mgmt.CaMgmtException
        | org.xipki.codec.exception.CodecException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  }

  /** Reads one certificate through the official client and converts it to the Console contract. */
  @Override
  public CertWithRevocationInfo getCert(String caName, BigInteger serialNumber)
      throws CaMgmtException {
    try {
      var value = official.getCert(caName, serialNumber);
      if (value == null) {
        return null;
      }
      var certificate = Crypto.X509Util.parseCert(value.cert().cert().getEncoded());
      return new CertWithRevocationInfo(
          new CertWithDbId(certificate), value.certprofile(), revocation(value.revInfo()));
    } catch (org.xipki.ca.api.mgmt.CaMgmtException | CertificateException ex) {
      throw new CaMgmtException(ex.getMessage(), ex);
    }
  }

  /** Revokes one certificate through the official XiPKI client without automatic retry. */
  @Override
  public void revokeCertificate(
      String caName, BigInteger serialNumber, CrlReason reason, Instant invalidityTime)
      throws CaMgmtException {
    var officialReason = org.xipki.pkix.cert.CrlReason.valueOf(reason.name());
    mutate(
        () ->
            official.revokeCertificate(
                caName, serialNumber, officialReason, invalidityTime));
  }

  /** Removes certificate-hold status through the official XiPKI client. */
  @Override
  public void unsuspendCertificate(String caName, BigInteger serialNumber)
      throws CaMgmtException {
    mutate(() -> official.unsuspendCertificate(caName, serialNumber));
  }

  /** Removes one certificate record through the official XiPKI client. */
  @Override
  public void removeCertificate(String caName, BigInteger serialNumber) throws CaMgmtException {
    mutate(() -> official.removeCertificate(caName, serialNumber));
  }

  /** Issues a certificate from a CSR through the official client without changing DER bytes. */
  @Override
  public Crypto.X509Cert generateCertificate(
      String caName,
      String profileName,
      byte[] encodedCsr,
      Instant notBefore,
      Instant notAfter)
      throws CaMgmtException {
    try {
      var certificate =
          official.generateCertificate(caName, profileName, encodedCsr, notBefore, notAfter);
      return certificate == null
          ? null
          : Crypto.X509Util.parseCert(certificate.getEncoded());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not convert issued certificate", ex);
    }
  }

  /** Generates a private key and certificate through the official client without re-encoding. */
  @Override
  public CaDomain.KeyCertBytesPair generateKeyCert(
      String caName,
      String profileName,
      String subject,
      Instant notBefore,
      Instant notAfter)
      throws CaMgmtException {
    try {
      var pair = official.generateKeyCert(caName, profileName, subject, notBefore, notAfter);
      return pair == null ? null : new CaDomain.KeyCertBytesPair(pair.key(), pair.cert());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Issues a cross certificate through the official client without changing binary inputs. */
  @Override
  public Crypto.X509Cert generateCrossCertificate(
      String caName,
      String profileName,
      byte[] encodedCsr,
      byte[] encodedTargetCert,
      Instant notBefore,
      Instant notAfter)
      throws CaMgmtException {
    try {
      var certificate =
          official.generateCrossCertificate(
              caName, profileName, encodedCsr, encodedTargetCert, notBefore, notAfter);
      return certificate == null
          ? null
          : Crypto.X509Util.parseCert(certificate.getEncoded());
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    } catch (CertificateException ex) {
      throw new CaMgmtException("could not convert issued cross certificate", ex);
    }
  }

  /** Lists supported signer types through the official XiPKI client. */
  @Override
  public Set<String> getSupportedSignerTypes() throws CaMgmtException {
    try {
      return official.getSupportedSignerTypes();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Lists supported certificate profile types through the official XiPKI client. */
  @Override
  public Set<String> getSupportedCertprofileTypes() throws CaMgmtException {
    try {
      return official.getSupportedCertprofileTypes();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Lists supported publisher types through the official XiPKI client. */
  @Override
  public Set<String> getSupportedPublisherTypes() throws CaMgmtException {
    try {
      return official.getSupportedPublisherTypes();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Imports a configuration archive through the official management client. */
  @Override
  public void loadConfAndClose(InputStream zippedConfStream) throws CaMgmtException, IOException {
    try {
      official.loadConfAndClose(zippedConfStream);
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Exports the selected CA configuration through the official management client. */
  @Override
  public InputStream exportConf(List<String> caNames) throws CaMgmtException {
    try {
      return official.exportConf(caNames);
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Reads PKCS#11 token information through the official management client. */
  @Override
  public String getTokenInfoP11(String moduleName, Integer slotIndex, boolean verbose)
      throws CaMgmtException {
    try {
      return official.getTokenInfoP11(moduleName, slotIndex, verbose);
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  /** Decodes the official CA codec shape into the Console's stable domain model. */
  private static CaEntry caEntry(JsonMap value) throws Exception {
    var base =
        new BaseCaInfo(
            value.getNnString("signerType"), permissions(value.getObject("permissions")));
    populateBase(base, value);
    var ca =
        new CaEntry(
            base,
            new NameId(value.getInt("id"), value.getNnString("name")),
            value.getNnString("signerConf"));
    byte[] cert = value.getBytes("cert");
    if (cert != null) {
      ca.setCert(Crypto.X509Util.parseCert(cert));
    }
    var chain = value.getBytesList("certchain");
    if (chain != null) {
      var list = new ArrayList<Crypto.X509Cert>();
      for (var encoded : chain) {
        list.add(Crypto.X509Util.parseCert(encoded));
      }
      ca.setCertchain(list);
    }
    return ca;
  }

  /** Accepts both list and bit-mask permission encodings emitted by supported XiPKI codecs. */
  private static Permissions permissions(Object value) throws Exception {
    if (value instanceof JsonList list) {
      return new Permissions(list.toStringList());
    }
    if (value instanceof Number number) {
      return new Permissions(number.intValue());
    }
    throw new IllegalArgumentException("Permissions required");
  }

  /** Applies optional official CA fields while retaining the Console domain defaults. */
  private static void populateBase(BaseCaInfo base, JsonMap value) throws Exception {
    for (String name : List.of("expirationPeriod", "keepExpiredCertDays", "numCrls", "snSize")) {
      Integer fieldValue = value.getInt(name);
      if (fieldValue != null) {
        base.getClass()
            .getMethod(
                "set" + Character.toUpperCase(name.charAt(0)) + name.substring(1), int.class)
            .invoke(base, fieldValue);
      }
    }
    if (value.getLong("nextCrlNo") != null) {
      base.setNextCrlNo(value.getLong("nextCrlNo"));
    }
    if (value.getBool("saveCert") != null) {
      base.setSaveCert(value.getBool("saveCert"));
    }
    if (value.getBool("saveKeypair") != null) {
      base.setSaveKeypair(value.getBool("saveKeypair"));
    }
    base.setMaxValidity(Validity.getInstance(value.getNnString("maxValidity")));
    if (value.getString("status") != null) {
      base.setStatus(CaStatus.forName(value.getString("status")));
    }
    if (value.getString("validityMode") != null) {
      base.setValidityMode(ValidityMode.forName(value.getString("validityMode")));
    }
    base.setKeypairGenNames(value.getStringList("keypairGenNames"));
    base.setCrlSignerName(value.getString("crlSignerName"));
    JsonMap uris = value.getMap("caUris");
    if (uris != null) {
      base.setCaUris(
          new CaUris(
              uris.getStringList("cacertUris"),
              uris.getStringList("ocspUris"),
              uris.getStringList("crlUris"),
              uris.getStringList("deltaCrlUris")));
    }
    if (value.getMap("crlControl") != null) {
      base.setCrlControl(
          new CrlControl(ConfPairs.parse(value.getMap("crlControl")).getEncoded()));
    }
    if (value.getMap("ctlogControl") != null) {
      base.setCtlogControl(
          new CtlogControl(ConfPairs.parse(value.getMap("ctlogControl")).getEncoded()));
    }
    if (value.getMap("revokeSuspendedControl") != null) {
      base.setRevokeSuspendedControl(
          new RevokeSuspendedControl(
              ConfPairs.parse(value.getMap("revokeSuspendedControl")).getEncoded()));
    }
    base.setExtraControl(ConfPairs.parse(value.getMap("extraControl")));
    Object revocation = value.getObject("revocationInfo");
    if (revocation instanceof JsonMap map) {
      base.setRevocationInfo(jsonRevocation(map));
    } else if (revocation instanceof String text) {
      var pairs = new ConfPairs(text);
      base.setRevocationInfo(
          new CertRevocationInfo(
              CrlReason.forNameOrText(pairs.value("reason")),
              Instant.ofEpochSecond(Long.parseLong(pairs.value("revocationTime"))),
              pairs.value("invalidityTime") == null
                  ? null
                  : Instant.ofEpochSecond(Long.parseLong(pairs.value("invalidityTime")))));
    }
  }

  /** Decodes JSON revocation metadata from the official CA codec representation. */
  private static CertRevocationInfo jsonRevocation(JsonMap value) throws Exception {
    return new CertRevocationInfo(
        CrlReason.forNameOrText(value.getNnString("reason")),
        value.getNnInstant("revocationTime"),
        value.getInstant("invalidityTime"));
  }

  /** Preserves the official error as the cause while exposing the Console's stable exception type. */
  private static CaMgmtException translate(org.xipki.ca.api.mgmt.CaMgmtException ex) {
    return new CaMgmtException(ex.getMessage(), ex);
  }

  /** Converts official revocation metadata without leaking XiPKI transport types to controllers. */
  private static CertRevocationInfo revocation(
      org.xipki.pkix.cert.CertRevocationInfo value) {
    return value == null
        ? null
        : new CertRevocationInfo(
            CrlReason.valueOf(value.reason().name()),
            value.revocationTime(),
            value.invalidityTime());
  }

  /** Converts the official resource identity without exposing SDK types to controllers. */
  private static CaDomain.NameId nameId(org.xipki.util.misc.NameId value) {
    return new CaDomain.NameId(value.id(), value.name());
  }

  /** Converts a Console resource identity for official mutation requests. */
  private static org.xipki.util.misc.NameId officialNameId(CaDomain.NameId value) {
    return new org.xipki.util.misc.NameId(value.id(), value.name());
  }

  /** Converts the complete Console CA definition to XiPKI's official management object. */
  private static org.xipki.ca.api.mgmt.entry.CaEntry officialCaEntry(CaEntry value)
      throws Exception {
    var source = value.getBase();
    var base =
        new org.xipki.ca.api.mgmt.entry.BaseCaInfo(
            source.getSignerType(),
            new org.xipki.ca.api.mgmt.Permissions(source.getPermissions().getValue()));
    if (source.getCaUris() != null) {
      var uris = source.getCaUris();
      base.setCaUris(
          new org.xipki.ca.api.mgmt.CaUris(
              uris.getCacertUris(),
              uris.getOcspUris(),
              uris.getCrlUris(),
              uris.getDeltaCrlUris()));
    }
    if (source.getCrlControl() != null) {
      base.setCrlControl(
          new org.xipki.ca.api.mgmt.CrlControl(source.getCrlControl().getConf()));
    }
    if (source.getCtlogControl() != null) {
      base.setCtlogControl(
          new org.xipki.ca.api.mgmt.CtlogControl(source.getCtlogControl().getConf()));
    }
    if (source.getRevokeSuspendedControl() != null) {
      base.setRevokeSuspendedControl(
          new org.xipki.ca.api.mgmt.RevokeSuspendedControl(
              source.getRevokeSuspendedControl().getConf()));
    }
    if (source.getExtraControl() != null) {
      base.setExtraControl(new org.xipki.codec.util.ConfPairs(source.getExtraControl().getEncoded()));
    }
    base.setCrlSignerName(source.getCrlSignerName());
    base.setExpirationPeriod(source.getExpirationPeriod());
    base.setKeepExpiredCertDays(source.getKeepExpiredCertDays());
    base.setKeypairGenNames(source.getKeypairGenNames());
    base.setMaxValidity(source.getMaxValidity());
    base.setNextCrlNo(source.getNextCrlNo());
    base.setNumCrls(source.getNumCrls());
    base.setSaveCert(source.isSaveCert());
    base.setSaveKeypair(source.isSaveKeypair());
    base.setSnSize(source.getSnSize());
    base.setStatus(org.xipki.ca.api.mgmt.CaStatus.valueOf(source.getStatus().name()));
    base.setValidityMode(
        org.xipki.ca.api.profile.ctrl.ValidityMode.valueOf(source.getValidityMode().name()));
    if (source.getRevocationInfo() != null) {
      var revocation = source.getRevocationInfo();
      base.setRevocationInfo(
          new org.xipki.pkix.cert.CertRevocationInfo(
              org.xipki.pkix.cert.CrlReason.valueOf(revocation.reason().name()),
              revocation.revocationTime(),
              revocation.invalidityTime()));
    }

    var result =
        new org.xipki.ca.api.mgmt.entry.CaEntry(
            base, officialNameId(value.getIdent()), value.getSignerConf());
    if (value.getCert() != null) {
      result.setCert(org.xipki.pkix.util.X509Util.parseCert(value.getCert().getEncoded()));
    }
    if (value.getCertchain() != null) {
      var chain = new ArrayList<org.xipki.pkix.cert.X509Cert>(value.getCertchain().size());
      for (var certificate : value.getCertchain()) {
        chain.add(org.xipki.pkix.util.X509Util.parseCert(certificate.getEncoded()));
      }
      result.setCertchain(chain);
    }
    return result;
  }

  /** Converts a nullable Console CA patch to XiPKI's official change object. */
  private static org.xipki.ca.api.mgmt.entry.ChangeCaEntry officialChangeCaEntry(
      ChangeCaEntry value) {
    var result =
        new org.xipki.ca.api.mgmt.entry.ChangeCaEntry(officialNameId(value.getIdent()));
    if (value.getStatus() != null) {
      result.setStatus(org.xipki.ca.api.mgmt.CaStatus.valueOf(value.getStatus().name()));
    }
    result.setMaxValidity(value.getMaxValidity());
    if (value.getValidityMode() != null) {
      result.setValidityMode(
          org.xipki.ca.api.profile.ctrl.ValidityMode.valueOf(
              value.getValidityMode().name()));
    }
    result.setPermissions(value.getPermissions());
    result.setSerialNoLen(value.getSerialNoLen());
    result.setNumCrls(value.getNumCrls());
    result.setExpirationPeriod(value.getExpirationPeriod());
    result.setKeepExpiredCertDays(value.getKeepExpiredCertDays());
    result.setSaveCert(value.getSaveCert());
    result.setSaveKeypair(value.getSaveKeypair());
    result.setKeypairGenNames(value.getKeypairGenNames());
    result.setCrlSignerName(value.getCrlSignerName());
    result.setCrlControl(value.getCrlControl());
    result.setCtlogControl(value.getCtlogControl());
    result.setRevokeSuspendedControl(value.getRevokeSuspendedControl());
    result.setExtraControl(value.getExtraControl());
    if (value.getCaUris() != null) {
      var uris = value.getCaUris();
      result.setCaUris(
          new org.xipki.ca.api.mgmt.CaUris(
              uris.getCacertUris(),
              uris.getOcspUris(),
              uris.getCrlUris(),
              uris.getDeltaCrlUris()));
    }
    result.setSignerType(value.getSignerType());
    result.setSignerConf(value.getSignerConf());
    result.setEncodedCert(value.getEncodedCert());
    result.setEncodedCertchain(value.getEncodedCertchain());
    return result;
  }

  /** Converts a CRL by its canonical DER bytes so controllers remain independent of SDK types. */
  private static Crypto.X509Crl crl(org.xipki.pkix.cert.X509Crl value)
      throws CaMgmtException {
    if (value == null) {
      return null;
    }
    try {
      return new Crypto.X509Crl(value.getEncoded());
    } catch (GeneralSecurityException ex) {
      throw new CaMgmtException("could not parse X.509 CRL", ex);
    }
  }

  /** Executes one official mutation and keeps the Console exception contract stable. */
  private static void mutate(OfficialMutation mutation) throws CaMgmtException {
    try {
      mutation.run();
    } catch (org.xipki.ca.api.mgmt.CaMgmtException ex) {
      throw translate(ex);
    }
  }

  @FunctionalInterface
  private interface OfficialMutation {
    void run() throws org.xipki.ca.api.mgmt.CaMgmtException;
  }
}
