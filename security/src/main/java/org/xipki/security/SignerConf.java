// Copyright (c) 2013-2026 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security;

import org.xipki.security.util.X509Util;
import org.xipki.util.codec.Args;
import org.xipki.util.codec.Hex;
import org.xipki.util.conf.ConfPairs;
import org.xipki.util.conf.InvalidConfException;
import org.xipki.util.extra.misc.CollectionUtil;

import java.security.NoSuchAlgorithmException;
import java.util.List;

/**
 * Configuration of {@link ConcurrentContentSigner}.
 *
 * @author Lijun Liao (xipki)
 * @since 2.0.0
 */

public class SignerConf {

  public static final String name_hash = "hash";

  public static final String name_mode = "mode";

  public static final String name_password = "password";

  public static final String name_keystore = "keystore";

  public static final String name_algo = "algo";

  public static final String name_parallelism = "parallelism";

  // PKCS#11
  public static final String name_module = "module";

  public static final String name_slot = "slot";

  public static final String name_slotId = "slot-id";

  public static final String name_keyId = "key-id";

  public static final String name_keyLabel = "key-label";

  private final ConfPairs confPairs;

  private CreateSignerCallback callback;

  private List<X509Cert> peerCertificates;

  public SignerConf() {
    this.confPairs = new ConfPairs();
  }

  public SignerConf(ConfPairs conf) {
    this.confPairs = Args.notNull(conf, "conf");
  }

  public SignerConf(String conf) {
    this.confPairs = new ConfPairs(Args.notBlank(conf, "conf"));
  }

  public SignerConf copy() {
    SignerConf copy = new SignerConf(confPairs);
    copy.callback = callback;
    copy.peerCertificates = peerCertificates;
    return copy;
  }

  public SignerConf setHash(HashAlgo hashAlgo) {
    return putPair(name_hash, hashAlgo.getJceName());
  }

  public HashAlgo getHash() throws NoSuchAlgorithmException {
    String str = value(name_algo);
    return str == null ? null : HashAlgo.getInstance(str);
  }

  public SignerConf setAlgo(SignAlgo signAlgo) {
    return putPair(name_algo, signAlgo.getJceName());
  }

  public SignAlgo getAlgo() throws InvalidConfException {
    String str = value(name_algo);
    try {
      return str == null ? null : SignAlgo.getInstance(str);
    } catch (NoSuchAlgorithmException e) {
      throw new InvalidConfException(e);
    }
  }

  public SignerConf setMode(SignAlgoMode mode) {
    return putPair(name_mode, mode.name());
  }

  public SignAlgoMode getMode() throws InvalidConfException {
    String str = value(name_mode);
    try {
      return str == null ? null : SignAlgoMode.getInstance(str);
    } catch (NoSuchAlgorithmException e) {
      throw new InvalidConfException(e);
    }
  }

  public SignerConf setPassword(String password) {
    return putPair(name_password, Args.notBlank(password, "password"));
  }

  public String getPassword() {
    return value(name_password);
  }

  public SignerConf setKeystore(String keystore) {
    return putPair(name_keystore,
        Args.notBlank(keystore, "keystore"));
  }

  public String getKeystore() {
    return value(name_keystore);
  }

  public SignerConf setParallelism(int parallelism) {
    return putPair(name_parallelism, Integer.toString(
        Args.positive(parallelism, "parallelism")));
  }

  public Integer getParallelism() throws InvalidConfException {
    String str = value(name_parallelism);
    if (str == null) {
      return null;
    }

    int ret;
    try {
      ret = Integer.parseInt(str);
    } catch (NumberFormatException ex) {
      throw new InvalidConfException("invalid parallelism " + str);
    }

    if (ret < 1) {
      throw new InvalidConfException("invalid parallelism " + str);
    }

    return ret;
  }

  public SignerConf setModule(String module) {
    return putPair(name_module, Args.notBlank(module, "module"));
  }

  public String getModule() {
    return value(name_module);
  }

  public SignerConf setSlot(int slot) {
    return putPair(name_slot, Integer.toString(
        Args.notNegative(slot, "slot")));
  }

  public Integer getSlot() {
    String str = value(name_slot);
    return str == null ? null : Integer.parseInt(str);
  }

  public SignerConf setSlotId(long slotId) {
    return putPair(name_slotId, Long.toString(slotId));
  }

  public Long getSlotId() {
    String str = value(name_slotId);
    return str == null ? null : Long.parseLong(str);
  }

  public SignerConf setKeyId(byte[] keyId) {
    return putPair(name_keyId, Hex.encode(keyId));
  }

  public byte[] getKeyId() {
    String str = value(name_keyId);
    return str == null ? null : Hex.decode(str);
  }

  public SignerConf setKeyLabel(String keyLabel) {
    return putPair(name_keyLabel, Args.notBlank(keyLabel, "keyLabel"));
  }

  public String getKeyLabel() {
    return value(name_keyLabel);
  }

  public SignerConf putPair(String name, String value) {
    confPairs.putPair(name, value);
    return this;
  }

  public SignerConf removePair(String name) {
    confPairs.removePair(name);
    return this;
  }

  public String value(String name) {
    return confPairs.value(name);
  }

  public ConfPairs getConf() {
    return confPairs;
  }

  public List<X509Cert> getPeerCertificates() {
    return peerCertificates;
  }

  public void setPeerCertificates(List<X509Cert> peerCertificates) {
    this.peerCertificates = peerCertificates;
  }

  public CreateSignerCallback getCallback() {
    return callback == null ? CreateSignerCallback.DEFAULT : callback;
  }

  public void setCallback(CreateSignerCallback callback) {
    this.callback = callback;
  }

  @Override
  public String toString() {
    return toString(true, true);
  }

  public String toString(boolean verbose, boolean ignoreSensitiveInfo) {
    String txtConf;
    if (ignoreSensitiveInfo) {
      txtConf = eraseSensitiveData(confPairs);
    } else {
      txtConf = confPairs.toString();
    }

    StringBuilder sb = new StringBuilder(txtConf.length() + 50);
    sb.append("conf: ");
    sb.append(txtConf);

    sb.append("\npeer Certificates: ");
    if (CollectionUtil.isEmpty(peerCertificates)) {
      sb.append("null");
    } else {
      for (int i = 0; i < peerCertificates.size(); i++) {
        sb.append("\ncert[").append(i).append("]:\n");
        sb.append(X509Util.formatCert(peerCertificates.get(i), verbose));
      }
    }

    return sb.toString();
  } // method toString

  public static String eraseSensitiveData(ConfPairs conf) {
    if (conf == null) {
      return "";
    }

    try {
      return conf.toStringOmitSensitive("password");
    } catch (Exception ex) {
      return conf.toString();
    }
  } // method eraseSensitiveData

  public static String eraseSensitiveData(String conf) {
    if (conf == null || !conf.toLowerCase().contains("password")) {
      return conf;
    }

    try {
      return new ConfPairs(conf).toStringOmitSensitive("password");
    } catch (Exception ex) {
      return conf;
    }
  }

}
