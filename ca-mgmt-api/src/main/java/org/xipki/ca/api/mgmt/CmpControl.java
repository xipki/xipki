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

package org.xipki.ca.api.mgmt;

import org.xipki.security.AlgorithmValidator;
import org.xipki.security.CollectionAlgorithmValidator;
import org.xipki.security.HashAlgo;
import org.xipki.security.SignAlgo;
import org.xipki.util.*;

import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * CMP control.
 *
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpControl {

  public static final String ALGO_DELIMITER = ":";

  public static final String KEY_CONFIRM_CERT = "confirm.cert";

  public static final String KEY_SEND_CA = "send.ca";

  public static final String KEY_SEND_CERTCHAIN = "send.certchain";

  public static final String KEY_SEND_RESPONDER = "send.responder";

  public static final String KEY_MESSAGETIME_REQUIRED = "messagetime.required";

  public static final String KEY_MESSAGETIME_BIAS = "messagetime.bias";

  public static final String KEY_CONFIRM_WAITTIME = "confirm.waittime";

  public static final String KEY_PROTECTION_SIGALGO = "protection.sigalgo";

  public static final String KEY_PROTECTION_PBM_OWF = "protection.pbm.owf";

  public static final String KEY_PROTECTION_PBM_MAC = "protection.pbm.mac";

  public static final String KEY_PROTECTION_PBM_IC = "protection.pbm.ic";

  public static final String KEY_GROUP_ENROLL = "group.enroll";

  public static final String KEY_RR_AKI_REQUIRED = "rr.aki.required";

  private static final int DFLT_MESSAGE_TIME_BIAS = 300; // 300 seconds

  private static final int DFLT_CONFIRM_WAIT_TIME = 300; // 300 seconds

  private static final int DFLT_PBM_ITERATIONCOUNT = 10240;

  private final String conf;

  private final boolean confirmCert;

  private final boolean sendCaCert;

  private final boolean sendCertChain;

  private final boolean messageTimeRequired;

  private final boolean sendResponderCert;

  private final int messageTimeBias;

  private final int confirmWaitTime;

  private final long confirmWaitTimeMs;

  private final boolean groupEnroll;

  private final boolean rrAkiRequired;

  private HashAlgo responsePbmOwf;

  private List<HashAlgo> requestPbmOwfs;

  private SignAlgo responsePbmMac;

  private List<SignAlgo> requestPbmMacs;

  private int responsePbmIterationCount = DFLT_PBM_ITERATIONCOUNT;

  private final CollectionAlgorithmValidator sigAlgoValidator;

  public CmpControl(String conf)
      throws InvalidConfException {
    ConfPairs pairs = new ConfPairs(conf);
    this.confirmCert = getBoolean(pairs, KEY_CONFIRM_CERT, false);
    this.sendCaCert = getBoolean(pairs, KEY_SEND_CA, false);
    this.sendCertChain = getBoolean(pairs, KEY_SEND_CERTCHAIN, false);
    this.sendResponderCert = getBoolean(pairs, KEY_SEND_RESPONDER, true);
    this.groupEnroll = getBoolean(pairs, KEY_GROUP_ENROLL, false);
    this.messageTimeRequired = getBoolean(pairs, KEY_MESSAGETIME_REQUIRED, true);
    this.messageTimeBias = getInt(pairs, KEY_MESSAGETIME_BIAS, DFLT_MESSAGE_TIME_BIAS);
    this.rrAkiRequired = getBoolean(pairs, KEY_RR_AKI_REQUIRED, false);
    this.confirmWaitTime = getInt(pairs, KEY_CONFIRM_WAITTIME, DFLT_CONFIRM_WAIT_TIME);
    if (this.confirmWaitTime < 0) {
      throw new InvalidConfException("invalid " + KEY_CONFIRM_WAITTIME);
    }
    this.confirmWaitTimeMs = this.confirmWaitTime * 1000L;

    // protection algorithms
    String key = KEY_PROTECTION_SIGALGO;
    String str = pairs.value(key);
    if (str == null) {
      throw new InvalidConfException(key + " is not set");
    }
    Set<String> algos = splitAlgos(str);
    try {
      this.sigAlgoValidator = CollectionAlgorithmValidator.buildAlgorithmValidator(algos);
    } catch (NoSuchAlgorithmException ex) {
      throw new InvalidConfException("invalid " + key + ": " + str, ex);
    }

    algos = this.sigAlgoValidator.getAlgoNames();
    pairs.putPair(key, algosAsString(algos));

    // PasswordBasedMac
    str = pairs.value(KEY_PROTECTION_PBM_OWF);
    // CHECKSTYLE:SKIP
    List<String> listOwfAlgos = StringUtil.isBlank(str) ? null
        : StringUtil.split(str, ALGO_DELIMITER);

    // PasswordBasedMac.mac
    str = pairs.value(KEY_PROTECTION_PBM_MAC);
    List<String> listMacAlgos = StringUtil.isBlank(str) ? null
        : StringUtil.split(str, ALGO_DELIMITER);

    str = pairs.value(KEY_PROTECTION_PBM_IC);
    Integer pbmIterationCount = (str == null) ? null : Integer.parseInt(str);

    initPbm(pairs, listOwfAlgos, listMacAlgos, pbmIterationCount);

    this.conf = pairs.getEncoded();
  } // constructor

  public CmpControl(Boolean confirmCert, Boolean sendCaCert, Boolean sendCertChain,
      Boolean messageTimeRequired, Boolean sendResponderCert, Boolean rrAkiRequired,
      Integer messageTimeBias, Integer confirmWaitTime, Boolean groupEnroll,
      List<String> sigAlgos, List<String> pbmOwfs, List<String> pbmMacs, Integer pbmIterationCount)
      throws InvalidConfException {
    if (confirmWaitTime != null) {
      Args.notNegative(confirmWaitTime, "confirmWaitTime");
    }

    ConfPairs pairs = new ConfPairs();

    this.confirmCert = confirmCert != null && confirmCert;
    pairs.putPair(KEY_CONFIRM_CERT, Boolean.toString(this.confirmCert));

    this.sendCaCert = sendCaCert != null && sendCaCert;
    pairs.putPair(KEY_SEND_CA, Boolean.toString(this.sendCaCert));

    this.sendCertChain = sendCertChain != null && sendCertChain;
    pairs.putPair(KEY_SEND_CERTCHAIN, Boolean.toString(this.sendCertChain));

    this.messageTimeRequired = messageTimeRequired == null || messageTimeRequired;
    pairs.putPair(KEY_MESSAGETIME_REQUIRED, Boolean.toString(this.messageTimeRequired));

    this.sendResponderCert = sendResponderCert == null || sendResponderCert;
    pairs.putPair(KEY_SEND_RESPONDER, Boolean.toString(this.sendResponderCert));

    this.rrAkiRequired = rrAkiRequired == null || rrAkiRequired;
    pairs.putPair(KEY_RR_AKI_REQUIRED, Boolean.toString(this.rrAkiRequired));

    this.messageTimeBias = (messageTimeBias == null) ? DFLT_MESSAGE_TIME_BIAS : messageTimeBias;
    pairs.putPair(KEY_MESSAGETIME_BIAS, Integer.toString(this.messageTimeBias));

    this.confirmWaitTime = (confirmWaitTime == null) ? DFLT_CONFIRM_WAIT_TIME : confirmWaitTime;
    pairs.putPair(KEY_CONFIRM_WAITTIME, Integer.toString(this.confirmWaitTime));

    this.confirmWaitTimeMs = this.confirmWaitTime * 1000L;

    this.groupEnroll = groupEnroll != null && groupEnroll;
    try {
      this.sigAlgoValidator = CollectionAlgorithmValidator.buildAlgorithmValidator(sigAlgos);
    } catch (NoSuchAlgorithmException ex) {
      throw new InvalidConfException("invalid sigAlgos", ex);
    }

    if (CollectionUtil.isNotEmpty(sigAlgos)) {
      pairs.putPair(KEY_PROTECTION_SIGALGO, algosAsString(this.sigAlgoValidator.getAlgoNames()));
    }

    // PasswordBasedMac
    initPbm(pairs, pbmOwfs, pbmMacs, pbmIterationCount);

    if (CollectionUtil.isNotEmpty(pbmOwfs)) {
      pairs.putPair(KEY_PROTECTION_PBM_OWF, algosAsString(pbmOwfs));
    }

    if (CollectionUtil.isNotEmpty(pbmMacs)) {
      pairs.putPair(KEY_PROTECTION_PBM_MAC, algosAsString(pbmMacs));
    }

    pairs.putPair(KEY_PROTECTION_PBM_IC, Integer.toString(this.responsePbmIterationCount));

    this.conf = pairs.getEncoded();
  } // constructor

  private void initPbm(ConfPairs pairs, List<String> pbmOwfs, List<String> pbmMacs,
      Integer pbmIterationCount)
          throws InvalidConfException {
    if (pbmIterationCount == null) {
      pbmIterationCount = DFLT_PBM_ITERATIONCOUNT;
    }

    if (CollectionUtil.isEmpty(pbmOwfs)) {
      pbmOwfs = Collections.singletonList("SHA256");
    }

    if (CollectionUtil.isEmpty(pbmMacs)) {
      pbmMacs = Collections.singletonList("HMACSHA256");
    }

    if (pbmIterationCount <= 0) {
      throw new InvalidConfException("invalid pbmIterationCount " + pbmIterationCount);
    }
    this.responsePbmIterationCount = pbmIterationCount;
    pairs.putPair(KEY_PROTECTION_PBM_IC, Integer.toString(pbmIterationCount));

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

      if (i == 0) {
        responsePbmOwf = ha;
      }
    }
    pairs.putPair(KEY_PROTECTION_PBM_OWF, algosAsString(canonicalizedAlgos));

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

      if (i == 0) {
        responsePbmMac = signAlgo;
      }
    }

    pairs.putPair(KEY_PROTECTION_PBM_MAC, algosAsString(canonicalizedAlgos));
  } // method initPbm

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

  public long getConfirmWaitTimeMs() {
    return confirmWaitTimeMs;
  }

  public boolean isSendCaCert() {
    return sendCaCert;
  }

  public boolean isSendCertChain() {
    return sendCertChain;
  }

  public boolean isRrAkiRequired() {
    return rrAkiRequired;
  }

  public boolean isSendResponderCert() {
    return sendResponderCert;
  }

  public boolean isGroupEnroll() {
    return groupEnroll;
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

  public String getConf() {
    return conf;
  }

  @Override
  public int hashCode() {
    return conf.hashCode();
  }

  @Override
  public String toString() {
    return toString(false);
  }

  public String toString(boolean verbose) {
    return StringUtil.concatObjects(
        "  confirm cert: ", confirmCert,
        "\n  send CA cert: ", sendCaCert,
        "\n  send CA cert chain: ", sendCertChain,
        "\n  message time required: ", messageTimeRequired,
        "\n  send responder cert: ", sendResponderCert,
        "\n  message time bias: ", messageTimeBias, "s",
        "\n  confirm waiting time: ", confirmWaitTime, "s",
        "\n  group enroll: ", groupEnroll,
        "\n  AKI in revocation request required: ", rrAkiRequired,
        "\n  signature algorithms: ",
            CollectionUtil.sort(sigAlgoValidator.getAlgoNames()),
        (verbose ? "\n  encoded: " : ""), (verbose ? conf : ""));
  } // method toString

  @Override
  public boolean equals(Object obj) {
    if (this == obj) {
      return true;
    } else if (!(obj instanceof CmpControl)) {
      return false;
    }

    return conf.equals(((CmpControl) obj).conf);
  } // method equals

  private static boolean getBoolean(ConfPairs pairs, String key, boolean defaultValue) {
    String str = pairs.value(key);
    boolean ret = StringUtil.isBlank(str) ? defaultValue : Boolean.parseBoolean(str);
    pairs.putPair(key, Boolean.toString(ret));
    return ret;
  } // method getBoolean

  private static int getInt(ConfPairs pairs, String key, int defaultValue) {
    String str = pairs.value(key);
    int ret = StringUtil.isBlank(str) ? defaultValue : Integer.parseInt(str);
    pairs.putPair(key, Integer.toString(ret));
    return ret;
  } // method getInt

  private static String algosAsString(Collection<String> algos) {
    return StringUtil.collectionAsString(algos, ALGO_DELIMITER);
  }

  private static Set<String> splitAlgos(String encoded) {
    return StringUtil.splitAsSet(encoded, ALGO_DELIMITER);
  }

}
