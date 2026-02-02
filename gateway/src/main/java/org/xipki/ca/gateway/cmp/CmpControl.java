// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.ca.gateway.cmp;

import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.security.verify.AlgorithmValidator;
import org.xipki.security.verify.CollectionAlgorithmValidator;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.CollectionUtil;
import org.xipki.util.extra.type.EmbedCertsMode;

import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * CMP control.
 *
 * @author Lijun Liao (xipki)
 */

public class CmpControl {

  private static final Duration DFLT_MESSAGE_TIME_BIAS =
      Duration.ofSeconds(300); // 300 seconds

  private static final Duration DFLT_CONFIRM_WAIT_TIME =
      Duration.ofSeconds(300); // 300 seconds

  private static final int DFLT_PBM_ITERATIONCOUNT = 10240;

  private final boolean confirmCert;

  private final boolean sendCaCert;

  private final boolean sendCertChain;

  private final boolean messageTimeRequired;

  private final boolean sendResponderCert;

  private final Duration messageTimeBias;

  private final Duration confirmWaitTime;

  private HashAlgo responsePbmOwf;

  private final List<HashAlgo> requestPbmOwfs;

  private SignAlgo responsePbmMac;

  private final List<SignAlgo> requestPbmMacs;

  private final int responsePbmIterationCount;

  private final CollectionAlgorithmValidator sigAlgoValidator;

  public CmpControl(CmpControlConf conf) throws InvalidConfException {
    this.confirmCert = getBoolean(conf.confirmCert(), false);
    this.sendCaCert = getBoolean(conf.sendCaCert(), false);
    this.sendCertChain = getBoolean(conf.sendCertChain(), false);
    this.sendResponderCert = getBoolean(conf.sendResponderCert(), true);
    this.messageTimeRequired = getBoolean(
        conf.messageTimeRequired(), true);
    this.messageTimeBias = conf.messageTimeBias() == null
        ? DFLT_MESSAGE_TIME_BIAS
        : Duration.ofSeconds(Math.abs(conf.messageTimeBias()));
    this.confirmWaitTime = conf.confirmWaitTime() == null
        ? DFLT_CONFIRM_WAIT_TIME
        : Duration.ofSeconds(Math.abs(conf.confirmWaitTime()));

    // protection algorithms
    List<String> requestSigAlgos = conf.requestSigAlgos();
    if (CollectionUtil.isEmpty(requestSigAlgos)) {
      throw new InvalidConfException("requestSigAlgos is not set");
    }
    try {
      this.sigAlgoValidator = CollectionAlgorithmValidator
          .buildAlgorithmValidator(requestSigAlgos);
    } catch (NoSuchAlgorithmException ex) {
      throw new InvalidConfException("invalid signature algorithm", ex);
    }

    // PBM
    try {
      if (conf.responsePbmMac() != null) {
        this.responsePbmMac = SignAlgo.getInstance(conf.responsePbmMac());
      }

      if (conf.responsePbmOwf() != null) {
        this.responsePbmOwf = HashAlgo.getInstance(conf.responsePbmOwf());
      }
    } catch (NoSuchAlgorithmException ex) {
      throw new InvalidConfException(ex.getMessage(), ex);
    }

    // PasswordBasedMac
    List<String> pbmOwfs = conf.requestPbmOwfs();
    // PasswordBasedMac.mac
    List<String> pbmMacs = conf.requestPbmMacs();
    Integer pbmIterationCount = conf.responsePbmIterationCount();
    if (pbmIterationCount == null) {
      pbmIterationCount = DFLT_PBM_ITERATIONCOUNT;
    }

    if (pbmIterationCount <= 0) {
      throw new InvalidConfException(
          "invalid pbmIterationCount " + pbmIterationCount);
    }
    this.responsePbmIterationCount = pbmIterationCount;

    if (CollectionUtil.isEmpty(pbmOwfs)) {
      pbmOwfs = Collections.singletonList("SHA256");
    }

    if (CollectionUtil.isEmpty(pbmMacs)) {
      pbmMacs = Collections.singletonList("HMACSHA256");
    }

    this.requestPbmOwfs = new ArrayList<>(pbmOwfs.size());
    for (int i = 0; i < pbmOwfs.size(); i++) {
      String algo = pbmOwfs.get(i);
      HashAlgo ha;
      try {
        ha = HashAlgo.getInstance(algo);
      } catch (Exception ex) {
        throw new InvalidConfException("invalid pbmPwf " + algo, ex);
      }
      requestPbmOwfs.add(ha);

      if (i == 0 && responsePbmOwf == null) {
        responsePbmOwf = ha;
      }
    }

    // PasswordBasedMac.mac
    this.requestPbmMacs = new ArrayList<>(pbmMacs.size());
    for (int i = 0; i < pbmMacs.size(); i++) {
      String algo = pbmMacs.get(i);
      SignAlgo signAlgo;
      try {
        signAlgo = SignAlgo.getInstance(algo);
      } catch (NoSuchAlgorithmException ex) {
        throw new InvalidConfException("invalid pbmMac " + algo, ex);
      }
      requestPbmMacs.add(signAlgo);

      if (i == 0 && responsePbmMac == null) {
        responsePbmMac = signAlgo;
      }
    }
  } // method initPbm

  public EmbedCertsMode caCertsMode() {
    if (!sendCaCert) {
      return EmbedCertsMode.NONE;
    }
    return sendCertChain ? EmbedCertsMode.CHAIN : EmbedCertsMode.CERT;
  }

  public boolean isMessageTimeRequired() {
    return messageTimeRequired;
  }

  public boolean isConfirmCert() {
    return confirmCert;
  }

  public Duration messageTimeBias() {
    return messageTimeBias;
  }

  public Duration confirmWaitTime() {
    return confirmWaitTime;
  }

  public boolean isSendResponderCert() {
    return sendResponderCert;
  }

  public AlgorithmValidator sigAlgoValidator() {
    return sigAlgoValidator;
  }

  public HashAlgo responsePbmOwf() {
    return responsePbmOwf;
  }

  public SignAlgo responsePbmMac() {
    return responsePbmMac;
  }

  public int responsePbmIterationCount() {
    return responsePbmIterationCount;
  }

  public boolean isRequestPbmOwfPermitted(HashAlgo pbmOwf) {
    return requestPbmOwfs.contains(pbmOwf);
  }

  public boolean isRequestPbmMacPermitted(SignAlgo pbmMac) {
    return requestPbmMacs.contains(pbmMac);
  }

  private static boolean getBoolean(Boolean b, boolean defaultValue) {
    return b == null ? defaultValue : b;
  } // method getBoolean

}
