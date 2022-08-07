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

package org.xipki.ca.gateway.cmp;

import org.xipki.ca.sdk.CertsMode;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.CollectionAlgorithmValidator;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.util.CollectionUtil;
import org.xipki.util.exception.InvalidConfException;

import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * CMP control.
 *
 * @author Lijun Liao
 * @since 6.0.0
 */

public class CmpControl {

  private static final int DFLT_MESSAGE_TIME_BIAS = 300; // 300 seconds

  private static final int DFLT_CONFIRM_WAIT_TIME = 300; // 300 seconds

  private static final int DFLT_PBM_ITERATIONCOUNT = 10240;

  private final boolean confirmCert;

  private final boolean sendCaCert;

  private final boolean sendCertChain;

  private final boolean messageTimeRequired;

  private final boolean sendResponderCert;

  private final int messageTimeBias;

  private final int confirmWaitTime;

  private final int confirmWaitTimeMs;

  private HashAlgo responsePbmOwf;

  private List<HashAlgo> requestPbmOwfs;

  private SignAlgo responsePbmMac;

  private List<SignAlgo> requestPbmMacs;

  private int responsePbmIterationCount = DFLT_PBM_ITERATIONCOUNT;

  private final CollectionAlgorithmValidator sigAlgoValidator;

  public CmpControl(CmpControlConf conf)
      throws InvalidConfException {
    this.confirmCert = getBoolean(conf.getConfirmCert(), false);
    this.sendCaCert = getBoolean(conf.getSendCaCert(), false);
    this.sendCertChain = getBoolean(conf.getSendCertChain(), false);
    this.sendResponderCert = getBoolean(conf.getSendResponderCert(), true);
    this.messageTimeRequired = getBoolean(conf.getMessageTimeRequired(), true);
    this.messageTimeBias = getInt(conf.getMessageTimeBias(), DFLT_MESSAGE_TIME_BIAS);
    this.confirmWaitTime = getInt(conf.getConfirmWaitTime(), DFLT_CONFIRM_WAIT_TIME);
    if (this.confirmWaitTime < 0) {
      throw new InvalidConfException("invalid confirmWaitTime " + confirmWaitTime);
    }
    this.confirmWaitTimeMs = this.confirmWaitTime * 1000;

    // protection algorithms
    List<String> requestSigAlgos = conf.getRequestSigAlgos();
    if (CollectionUtil.isEmpty(requestSigAlgos)) {
      throw new InvalidConfException("requestSigAlgos is not set");
    }
    try {
      this.sigAlgoValidator =
          CollectionAlgorithmValidator.buildAlgorithmValidator(requestSigAlgos);
    } catch (NoSuchAlgorithmException ex) {
      throw new InvalidConfException("invalid signature algorithm", ex);
    }

    // PBM
    try {
      if (conf.getResponsePbmMac() != null) {
        this.responsePbmMac = SignAlgo.getInstance(conf.getResponsePbmMac());
      }

      if (conf.getResponsePbmOwf() != null) {
        this.responsePbmOwf = HashAlgo.getInstance(conf.getResponsePbmOwf());
      }
    } catch (NoSuchAlgorithmException ex) {
      throw new InvalidConfException(ex);
    }

    // PasswordBasedMac
    List<String> pbmOwfs = conf.getRequestPbmOwfs();
    // PasswordBasedMac.mac
    List<String> pbmMacs = conf.getRequestPbmMacs();
    Integer pbmIterationCount = conf.getResponsePbmIterationCount();
    if (pbmIterationCount == null) {
      pbmIterationCount = DFLT_PBM_ITERATIONCOUNT;
    }

    if (pbmIterationCount <= 0) {
      throw new InvalidConfException("invalid pbmIterationCount " + pbmIterationCount);
    }
    this.responsePbmIterationCount = pbmIterationCount;

    if (CollectionUtil.isEmpty(pbmOwfs)) {
      pbmOwfs = Collections.singletonList("SHA256");
    }

    if (CollectionUtil.isEmpty(pbmMacs)) {
      pbmMacs = Collections.singletonList("HMACSHA256");
    }

    this.requestPbmOwfs = new ArrayList<>(pbmOwfs.size());
    List<String> canonicalizedAlgos = new ArrayList<>(pbmOwfs.size());
    for (int i = 0; i < pbmOwfs.size(); i++) {
      String algo = pbmOwfs.get(i);
      HashAlgo ha;
      try {
        ha = HashAlgo.getInstance(algo);
      } catch (Exception ex) {
        throw new InvalidConfException("invalid pbmPwf " + algo, ex);
      }
      canonicalizedAlgos.add(ha.getJceName());
      requestPbmOwfs.add(ha);

      if (i == 0 && responsePbmOwf == null) {
        responsePbmOwf = ha;
      }
    }

    // PasswordBasedMac.mac
    canonicalizedAlgos.clear();
    this.requestPbmMacs = new ArrayList<>(pbmMacs.size());
    for (int i = 0; i < pbmMacs.size(); i++) {
      String algo = pbmMacs.get(i);
      SignAlgo signAlgo;
      try {
        signAlgo = SignAlgo.getInstance(algo);
      } catch (NoSuchAlgorithmException ex) {
        throw new InvalidConfException("invalid pbmMac " + algo, ex);
      }
      canonicalizedAlgos.add(signAlgo.getJceName());
      requestPbmMacs.add(signAlgo);

      if (i == 0 && responsePbmMac == null) {
        responsePbmMac = signAlgo;
      }
    }
  } // method initPbm

  public CertsMode getCaCertsMode() {
    if (!sendCaCert) {
      return CertsMode.NONE;
    }
    return sendCertChain ? CertsMode.CHAIN : CertsMode.CERT;
  }

  public boolean isMessageTimeRequired() {
    return messageTimeRequired;
  }

  public boolean isConfirmCert() {
    return confirmCert;
  }

  public int getMessageTimeBias() {
    return messageTimeBias;
  }

  public int getConfirmWaitTime() {
    return confirmWaitTime;
  }

  public int getConfirmWaitTimeMs() {
    return confirmWaitTimeMs;
  }

  public boolean isSendCaCert() {
    return sendCaCert;
  }

  public boolean isSendCertChain() {
    return sendCertChain;
  }

  public boolean isSendResponderCert() {
    return sendResponderCert;
  }

  public AlgorithmValidator getSigAlgoValidator() {
    return sigAlgoValidator;
  }

  public HashAlgo getResponsePbmOwf() {
    return responsePbmOwf;
  }

  public SignAlgo getResponsePbmMac() {
    return responsePbmMac;
  }

  public int getResponsePbmIterationCount() {
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

  private static int getInt(Integer i, int defaultValue) {
    return i == null ? defaultValue : i;
  } // method getInt

}
