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

package org.xipki.ca.mgmt.shell;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;

import org.apache.karaf.shell.api.action.Command;
import org.apache.karaf.shell.api.action.Completion;
import org.apache.karaf.shell.api.action.Option;
import org.apache.karaf.shell.api.action.lifecycle.Service;
import org.apache.karaf.shell.support.completers.FileCompleter;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.xipki.ca.mgmt.api.CaEntry;
import org.xipki.ca.mgmt.api.CaMgmtException;
import org.xipki.ca.mgmt.api.CertListInfo;
import org.xipki.ca.mgmt.api.CertListOrderBy;
import org.xipki.ca.mgmt.api.CertWithRevocationInfo;
import org.xipki.ca.mgmt.shell.CaActions.CaAction;
import org.xipki.security.CrlReason;
import org.xipki.security.util.X509Util;
import org.xipki.shell.CmdFailure;
import org.xipki.shell.Completers;
import org.xipki.shell.IllegalCmdParamException;
import org.xipki.util.DateUtil;
import org.xipki.util.InvalidConfException;
import org.xipki.util.IoUtil;
import org.xipki.util.StringUtil;

/**
 * TODO.
 * @author Lijun Liao
 *
 */
public class CertActions {

  @Command(scope = "ca", name = "cert-status",
      description = "show certificate status and save the certificate")
  @Service
  public static class CertStatus extends UnRevRmCertAction {

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
      CertWithRevocationInfo certInfo = caManager.getCert(caName, getSerialNumber());

      if (certInfo == null) {
        System.out.println("certificate unknown");
        return null;
      }

      String msg = StringUtil.concat("certificate profile: ", certInfo.getCertprofile(),
          "\nstatus: ",
          (certInfo.getRevInfo() == null ? "good" : "revoked with " + certInfo.getRevInfo()));
      println(msg);
      if (outputFile != null) {
        saveVerbose("saved certificate to file", outputFile,
            encodeCert(certInfo.getCert().getEncodedCert(), outform));
      }
      return null;
    }

  }

  public abstract static class CrlAction extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--outform", description = "output format of the CRL")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    protected abstract X509CRL retrieveCrl() throws Exception;

    @Override
    protected Object execute0() throws Exception {
      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("CA " + caName + " not available");
      }

      X509CRL crl = null;
      try {
        crl = retrieveCrl();
      } catch (Exception ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      if (crl == null) {
        throw new CmdFailure("received no CRL from server");
      }

      String outFile = getOutFile();
      if (outFile != null) {
        saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));
      }
      return null;
    }

    protected abstract String getOutFile();

  }

  @Command(scope = "ca", name = "enroll-cert", description = "enroll certificate")
  @Service
  public static class EnrollCert extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    private String caName;

    @Option(name = "--csr", required = true, description = "CSR file")
    @Completion(FileCompleter.class)
    private String csrFile;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outFile;

    @Option(name = "--profile", aliases = "-p", required = true, description = "profile name")
    @Completion(CaCompleters.ProfileNameCompleter.class)
    private String profileName;

    @Option(name = "--not-before", description = "notBefore, UTC time of format yyyyMMddHHmmss")
    private String notBeforeS;

    @Option(name = "--not-after", description = "notAfter, UTC time of format yyyyMMddHHmmss")
    private String notAfterS;

    @Override
    protected Object execute0() throws Exception {
      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("CA " + caName + " not available");
      }

      Date notBefore = StringUtil.isNotBlank(notBeforeS)
          ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notBeforeS) : null;

      Date notAfter = StringUtil.isNotBlank(notAfterS)
          ? DateUtil.parseUtcTimeyyyyMMddhhmmss(notAfterS) : null;

      byte[] encodedCsr = IoUtil.read(csrFile);

      X509Certificate cert = caManager.generateCertificate(caName, profileName, encodedCsr,
          notBefore, notAfter);
      saveVerbose("saved certificate to file", outFile, encodeCert(cert.getEncoded(), outform));

      return null;
    }

  }

  @Command(scope = "ca", name = "gencrl", description = "generate CRL")
  @Service
  public static class Gencrl extends CrlAction {

    @Option(name = "--out", aliases = "-o", description = "where to save the CRL")
    @Completion(FileCompleter.class)
    protected String outFile;

    @Override
    protected X509CRL retrieveCrl() throws Exception {
      return caManager.generateCrlOnDemand(caName);
    }

    @Override
    protected String getOutFile() {
      return outFile;
    }

  }

  @Command(scope = "ca", name = "get-cert", description = "get certificate")
  @Service
  public static class GetCert extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--serial", aliases = "-s", required = true, description = "serial number")
    private String serialNumberS;

    @Option(name = "--outform", description = "output format of the certificate")
    @Completion(Completers.DerPemCompleter.class)
    protected String outform = "der";

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the certificate")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
      CertWithRevocationInfo certInfo = caManager.getCert(caName, toBigInt(serialNumberS));

      if (certInfo == null) {
        System.out.println("certificate unknown");
        return null;
      }

      saveVerbose("certificate saved to file", outputFile,
          encodeCert(certInfo.getCert().getEncodedCert(), outform));
      return null;
    }

  }

  @Command(scope = "ca", name = "getcrl", description = "download CRL")
  @Service
  public static class Getcrl extends CrlAction {

    @Option(name = "--with-basecrl",
        description = "whether to retrieve the baseCRL if the current CRL is a delta CRL")
    private Boolean withBaseCrl = Boolean.FALSE;

    @Option(name = "--basecrl-out",
        description = "where to save the baseCRL\n(defaults to <out>-baseCRL)")
    @Completion(FileCompleter.class)
    private String baseCrlOut;

    @Option(name = "--out", aliases = "-o", required = true, description = "where to save the CRL")
    @Completion(FileCompleter.class)
    protected String outFile;

    @Override
    protected X509CRL retrieveCrl() throws Exception {
      return caManager.getCurrentCrl(caName);
    }

    @Override
    protected Object execute0() throws Exception {
      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("CA " + caName + " not available");
      }

      X509CRL crl = null;
      try {
        crl = retrieveCrl();
      } catch (Exception ex) {
        throw new CmdFailure("received no CRL from server: " + ex.getMessage());
      }

      if (crl == null) {
        throw new CmdFailure("received no CRL from server");
      }

      saveVerbose("saved CRL to file", outFile, encodeCrl(crl.getEncoded(), outform));

      if (withBaseCrl.booleanValue()) {
        byte[] octetString = crl.getExtensionValue(Extension.deltaCRLIndicator.getId());
        if (octetString != null) {
          if (baseCrlOut == null) {
            baseCrlOut = outFile + "-baseCRL";
          }

          byte[] extnValue = DEROctetString.getInstance(octetString).getOctets();
          BigInteger baseCrlNumber = ASN1Integer.getInstance(extnValue).getPositiveValue();

          try {
            crl = caManager.getCrl(caName, baseCrlNumber);
          } catch (Exception ex) {
            throw new CmdFailure("received no baseCRL from server: " + ex.getMessage());
          }

          if (crl == null) {
            throw new CmdFailure("received no baseCRL from server");
          } else {
            saveVerbose("saved baseCRL to file", baseCrlOut, encodeCrl(crl.getEncoded(), outform));
          }
        }
      }

      return null;
    } // method execute0

    @Override
    protected String getOutFile() {
      return outFile;
    }

  }

  @Command(scope = "ca", name = "get-request",
      description = "get the request to enroll certificate")
  @Service
  public static class GetRequest extends UnRevRmCertAction {

    @Option(name = "--out", aliases = "-o", required = true,
        description = "where to save the request")
    @Completion(FileCompleter.class)
    private String outputFile;

    @Override
    protected Object execute0() throws Exception {
      byte[] request = caManager.getCertRequest(caName, getSerialNumber());
      if (request == null) {
        System.out.println("unknown request unknown");
        return null;
      }

      saveVerbose("request saved to file", outputFile, request);
      return null;
    }

  }

  @Command(scope = "ca", name = "list-cert", description = "show a list of certificates")
  @Service
  public static class ListCert extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--subject", description = "the subject pattern, * is allowed.")
    protected String subjectPatternS;

    @Option(name = "--valid-from",
        description = "start UTC time when the certificate is still valid, in form of"
            + "yyyyMMdd or yyyyMMddHHmmss")
    private String validFromS;

    @Option(name = "--valid-to",
        description = "end UTC time when the certificate is still valid, in form of"
            + "yyyMMdd or yyyyMMddHHmmss")
    private String validToS;

    @Option(name = "-n", description = "maximal number of entries (between 1 and 1000)")
    private int num = 1000;

    @Option(name = "--order", description = "by which the result is ordered")
    @Completion(CaCompleters.CertListSortByCompleter.class)
    private String orderByS;

    /**
     * TODO.
     * @return comma-separated serial numbers (in hex).
     */
    @Override
    protected Object execute0() throws Exception {
      Date validFrom = getDate(validFromS);
      Date validTo = getDate(validToS);
      X500Name subjectPattern = null;
      if (StringUtil.isNotBlank(subjectPatternS)) {
        subjectPattern = new X500Name(subjectPatternS);
      }

      CertListOrderBy orderBy = null;
      if (orderByS != null) {
        orderBy = CertListOrderBy.forValue(orderByS);
        if (orderBy == null) {
          throw new IllegalCmdParamException("invalid order '" + orderByS + "'");
        }
      }

      List<CertListInfo> certInfos = caManager.listCertificates(caName, subjectPattern, validFrom,
          validTo, orderBy, num);
      final int n = certInfos.size();
      if (n == 0) {
        println("found no certificate");
        return null;
      }

      println("     | serial               | notBefore      | notAfter       | subject");
      println("-----+----------------------+----------------+----------------+-----------------");
      for (int i = 0; i < n; i++) {
        CertListInfo info = certInfos.get(i);
        println(format(i + 1, info));
      }

      return null;
    }

    private String format(int index, CertListInfo info) {
      return StringUtil.concat(StringUtil.formatAccount(index, 4), " | ",
          StringUtil.formatText(info.getSerialNumber().toString(16), 20), " | ",
          DateUtil.toUtcTimeyyyyMMddhhmmss(info.getNotBefore()), " | ",
          DateUtil.toUtcTimeyyyyMMddhhmmss(info.getNotAfter()), " | ", info.getSubject());
    }

    private Date getDate(String str) throws IllegalCmdParamException {
      if (str == null) {
        return null;
      }

      final int len = str.length();
      try {
        if (len == 8) {
          return DateUtil.parseUtcTimeyyyyMMdd(str);
        } else if (len == 14) {
          return DateUtil.parseUtcTimeyyyyMMddhhmmss(str);
        } else {
          throw new IllegalCmdParamException("invalid time " + str);
        }
      } catch (IllegalArgumentException ex) {
        throw new IllegalCmdParamException("invalid time " + str + ": " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "rm-cert", description = "remove certificate")
  @Service
  public static class RmCert extends UnRevRmCertAction {

    @Option(name = "--force", aliases = "-f", description = "without prompt")
    private Boolean force = Boolean.FALSE;

    @Override
    protected Object execute0() throws Exception {
      BigInteger serialNo = getSerialNumber();
      String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
      if (force || confirm("Do you want to remove " + msg, 3)) {
        try {
          caManager.removeCertificate(caName, serialNo);
          println("removed " + msg);
        } catch (CaMgmtException ex) {
          throw new CmdFailure("could not remove " + msg + ", error: " + ex.getMessage(), ex);
        }
      }
      return null;
    }

  }

  @Command(scope = "ca", name = "revoke-cert", description = "revoke certificate")
  @Service
  public static class RevokeCert extends UnRevRmCertAction {

    @Option(name = "--reason", aliases = "-r", required = true, description = "CRL reason")
    @Completion(Completers.ClientCrlReasonCompleter.class)
    private String reason;

    @Option(name = "--inv-date", description = "invalidity date, UTC time of format yyyyMMddHHmmss")
    private String invalidityDateS;

    @Override
    protected Object execute0() throws Exception {
      CrlReason crlReason = CrlReason.forNameOrText(reason);

      if (!CrlReason.PERMITTED_CLIENT_CRLREASONS.contains(crlReason)) {
        throw new InvalidConfException("reason " + reason + " is not permitted");
      }

      Date invalidityDate = null;
      if (isNotBlank(invalidityDateS)) {
        invalidityDate = DateUtil.parseUtcTimeyyyyMMddhhmmss(invalidityDateS);
      }

      BigInteger serialNo = getSerialNumber();
      String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
      try {
        caManager.revokeCertificate(caName, serialNo, crlReason, invalidityDate);
        println("revoked " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not revoke " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  @Command(scope = "ca", name = "unrevoke-cert", description = "unrevoke certificate")
  @Service
  public static class UnrevokeCert extends UnRevRmCertAction {

    @Override
    protected Object execute0() throws Exception {
      BigInteger serialNo = getSerialNumber();
      String msg = "certificate (serial number = 0x" + serialNo.toString(16) + ")";
      try {
        caManager.unrevokeCertificate(caName, serialNo);
        println("unrevoked " + msg);
        return null;
      } catch (CaMgmtException ex) {
        throw new CmdFailure("could not unrevoke " + msg + ", error: " + ex.getMessage(), ex);
      }
    }

  }

  public abstract static class UnRevRmCertAction extends CaAction {

    @Option(name = "--ca", required = true, description = "CA name")
    @Completion(CaCompleters.CaNameCompleter.class)
    protected String caName;

    @Option(name = "--cert", aliases = "-c",
        description = "certificate file\n"
            + "(either cert or serial must be specified)")
    @Completion(FileCompleter.class)
    protected String certFile;

    @Option(name = "--serial", aliases = "-s",
        description = "serial number\n(either cert or serial must be specified)")
    private String serialNumberS;

    protected BigInteger getSerialNumber()
        throws CmdFailure, IllegalCmdParamException, CertificateException, IOException,
          CaMgmtException  {
      CaEntry ca = caManager.getCa(caName);
      if (ca == null) {
        throw new CmdFailure("CA " + caName + " not available");
      }

      BigInteger serialNumber;
      if (serialNumberS != null) {
        serialNumber = toBigInt(serialNumberS);
      } else if (certFile != null) {
        X509Certificate caCert = ca.getCert();
        X509Certificate cert = X509Util.parseCert(new File(certFile));
        if (!X509Util.issues(caCert, cert)) {
          throw new CmdFailure("certificate '" + certFile + "' is not issued by CA " + caName);
        }
        serialNumber = cert.getSerialNumber();
      } else {
        throw new IllegalCmdParamException("neither serialNumber nor certFile is specified");
      }

      return serialNumber;
    }

  }

}
