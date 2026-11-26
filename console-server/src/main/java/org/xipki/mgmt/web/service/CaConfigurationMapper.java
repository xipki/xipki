// License Apache License 2.0

package org.xipki.mgmt.web.service;

import java.util.List;
import java.util.Locale;
import org.xipki.codec.util.ConfPairs;
import org.xipki.mgmt.web.ca.CaDomain.*;
import org.xipki.mgmt.web.ca.Crypto.X509Cert;
import org.xipki.mgmt.web.core.*;
import org.xipki.mgmt.web.dto.CaConfigurationRequest;
import org.xipki.mgmt.web.dto.CaConfigurationRequest.CaUrisRequest;
import org.xipki.util.conf.Validity;

/**
 * Explicit whitelist mapping; no generic JSON-to-engine configuration pass-through.
 *
 * @author palos
 */
public class CaConfigurationMapper {
  public ChangeCaEntry change(String name, CaConfigurationRequest r) {
    if (r == null) {
      throw new IllegalArgumentException("Configuration required");
    }
    try {
      ChangeCaEntry c = new ChangeCaEntry(new NameId(null, name(name)));
      if (r.status != null) {
        c.setStatus(CaStatus.forName(r.status));
      }
      if (r.maxValidity != null) {
        c.setMaxValidity(validity(r.maxValidity));
      }
      if (r.validityMode != null) {
        c.setValidityMode(ValidityMode.forName(r.validityMode));
      }
      if (r.permissions != null) {
        int bits = new Permissions(r.permissions).getValue();
        if ((bits & ~PermissionConstants.ALL) != 0) {
          throw new IllegalArgumentException("Unsupported permission bits");
        }
        c.setPermissions(r.permissions);
      }
      if (r.serialNoLen != null) {
        c.setSerialNoLen(r.serialNoLen);
      }
      if (r.numCrls != null && r.numCrls < 0) {
        throw new IllegalArgumentException("Invalid CRL retention");
      }
      if (r.expirationPeriod != null && r.expirationPeriod < 0) {
        throw new IllegalArgumentException("Invalid expiration period");
      }
      if (r.keepExpiredCertDays != null && r.keepExpiredCertDays < -1) {
        throw new IllegalArgumentException("Invalid retention");
      }
      c.setNumCrls(r.numCrls);
      c.setExpirationPeriod(r.expirationPeriod);
      c.setKeepExpiredCertDays(r.keepExpiredCertDays);
      c.setSaveCert(r.saveCert);
      c.setSaveKeypair(r.saveKeypair);
      c.setKeypairGenNames(r.keypairGenNames);
      c.setCrlSignerName(r.crlSignerName);
      if (r.crlControl != null && !"NULL".equalsIgnoreCase(r.crlControl)) {
        new CrlControl(r.crlControl);
      }
      if (r.ctlogControl != null && !"NULL".equalsIgnoreCase(r.ctlogControl)) {
        new CtlogControl(r.ctlogControl);
      }
      if (r.revokeSuspendedControl != null && !"NULL".equalsIgnoreCase(r.revokeSuspendedControl)) {
        new RevokeSuspendedControl(r.revokeSuspendedControl);
      }
      if (r.extraControl != null && !"NULL".equalsIgnoreCase(r.extraControl)) {
        new ConfPairs(r.extraControl);
      }
      c.setCrlControl(r.crlControl);
      c.setCtlogControl(r.ctlogControl);
      c.setRevokeSuspendedControl(r.revokeSuspendedControl);
      c.setExtraControl(r.extraControl);
      if (r.caUris != null) {
        c.setCaUris(
            new CaUris(
                r.caUris.cacertUris, r.caUris.ocspUris, r.caUris.crlUris, r.caUris.deltaCrlUris));
      }
      if (r.signerType != null || r.signerConf != null || r.key != null) {
        if (!Boolean.TRUE.equals(r.replaceSigner)) {
          throw new IllegalArgumentException("Explicit signer replacement required");
        }
        if (r.key == null || r.signerConf != null || r.signerType != null) {
          throw new IllegalArgumentException(
              "Replace signer using uploaded material or structured PKCS11 reference");
        }
      }
      if (r.encodedCert != null || r.encodedCertchain != null) {
        if (!Boolean.TRUE.equals(r.replaceCertificates)) {
          throw new IllegalArgumentException("Explicit certificate replacement required");
        }
        if (r.encodedCert != null) {
          var cert = CaKeyMaterialService.certificate(r.encodedCert);
          CaKeyMaterialService.requireCa(cert);
          c.setEncodedCert(cert.getEncoded());
        }
        if (r.encodedCertchain != null) {
          c.setEncodedCertchain(
              CaKeyMaterialService.certificates(r.encodedCertchain).stream()
                  .map(X509Cert::getEncoded)
                  .toList());
        }
      }
      return c;
    } catch (IllegalArgumentException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid CA configuration");
    }
  }

  public BaseCaInfo create(String signerType, CaConfigurationRequest request, Long nextCrlNo) {
    CaConfigurationRequest r = request == null ? new CaConfigurationRequest() : request;
    if (r.key != null
        || r.signerConf != null
        || r.signerType != null
        || r.encodedCert != null
        || r.encodedCertchain != null) {
      throw new IllegalArgumentException("Creation material belongs in dedicated fields");
    }
    ChangeCaEntry c = change("validation", r);
    try {
      var b =
          new BaseCaInfo(
              signerType, new Permissions(r.permissions == null ? List.of("all") : r.permissions));
      b.setStatus(c.getStatus() == null ? CaStatus.inactive : c.getStatus());
      b.setMaxValidity(c.getMaxValidity() == null ? validity("365d") : c.getMaxValidity());
      b.setNextCrlNo(nextCrlNo == null ? 1 : nextCrlNo);
      if (b.getNextCrlNo() < 1) {
        throw new IllegalArgumentException("CRL number must be positive");
      }
      if (c.getSerialNoLen() != null) {
        b.setSnSize(c.getSerialNoLen());
      }
      if (c.getNumCrls() != null) {
        b.setNumCrls(c.getNumCrls());
      }
      if (c.getExpirationPeriod() != null) {
        b.setExpirationPeriod(c.getExpirationPeriod());
      }
      if (c.getKeepExpiredCertDays() != null) {
        b.setKeepExpiredCertDays(c.getKeepExpiredCertDays());
      }
      if (c.getSaveCert() != null) {
        b.setSaveCert(c.getSaveCert());
      }
      if (c.getSaveKeypair() != null) {
        b.setSaveKeypair(c.getSaveKeypair());
      }
      if (c.getValidityMode() != null) {
        b.setValidityMode(c.getValidityMode());
      }
      b.setKeypairGenNames(c.getKeypairGenNames());
      b.setCrlSignerName(c.getCrlSignerName());
      b.setCaUris(c.getCaUris());
      if (c.getCrlControl() != null) {
        b.setCrlControl(new CrlControl(c.getCrlControl()));
      }
      if (c.getCtlogControl() != null) {
        b.setCtlogControl(new CtlogControl(c.getCtlogControl()));
      }
      if (c.getRevokeSuspendedControl() != null) {
        b.setRevokeSuspendedControl(new RevokeSuspendedControl(c.getRevokeSuspendedControl()));
      }
      if (c.getExtraControl() != null) {
        b.setExtraControl(new ConfPairs(c.getExtraControl()));
      }
      return b;
    } catch (IllegalArgumentException ex) {
      throw ex;
    } catch (Exception ex) {
      throw new IllegalArgumentException("Invalid CA configuration");
    }
  }

  public CaConfigurationRequest read(CaEntry entry) {
    var b = entry.getBase();
    var r = new CaConfigurationRequest();
    r.status = b.getStatus().name();
    r.maxValidity = b.getMaxValidity() == null ? null : b.getMaxValidity().toString();
    r.validityMode = b.getValidityMode().name();
    r.permissions = b.getPermissions().toPermissionTexts();
    r.serialNoLen = b.getSnSize();
    r.numCrls = b.getNumCrls();
    r.expirationPeriod = b.getExpirationPeriod();
    r.keepExpiredCertDays = b.getKeepExpiredCertDays();
    r.saveCert = b.isSaveCert();
    r.saveKeypair = b.isSaveKeypair();
    r.keypairGenNames = b.getKeypairGenNames();
    r.crlSignerName = b.getCrlSignerName();
    r.crlControl = b.getCrlControl() == null ? null : b.getCrlControl().getConf();
    r.ctlogControl = b.getCtlogControl() == null ? null : b.getCtlogControl().getConf();
    r.revokeSuspendedControl =
        b.getRevokeSuspendedControl() == null ? null : b.getRevokeSuspendedControl().getConf();
    r.extraControl = b.getExtraControl() == null ? null : b.getExtraControl().getEncoded();
    if (b.getCaUris() != null) {
      r.caUris = new CaUrisRequest();
      r.caUris.cacertUris = b.getCaUris().getCacertUris();
      r.caUris.ocspUris = b.getCaUris().getOcspUris();
      r.caUris.crlUris = b.getCaUris().getCrlUris();
      r.caUris.deltaCrlUris = b.getCaUris().getDeltaCrlUris();
    }
    return r;
  }

  private static Validity validity(String s) {
    if (!s.matches("[1-9][0-9]*[ymdh]")) {
      throw new IllegalArgumentException("Invalid validity");
    }
    return Validity.getInstance(s);
  }

  public static String name(String value) {
    if (value == null || !value.matches("[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}")) {
      throw new IllegalArgumentException("Invalid resource name");
    }
    return value.toLowerCase(Locale.ROOT);
  }
}
