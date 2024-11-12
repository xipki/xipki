// Copyright (c) 2013-2024 xipki. All rights reserved.
// License Apache License 2.0

package org.xipki.security.pkcs11.hsmproxy;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.pkcs11.wrapper.PKCS11Constants;
import org.xipki.pkcs11.wrapper.PKCS11Exception;
import org.xipki.pkcs11.wrapper.TokenException;
import org.xipki.security.pkcs11.P11Module;
import org.xipki.security.pkcs11.P11ModuleConf;
import org.xipki.security.pkcs11.P11Slot;
import org.xipki.security.pkcs11.P11SlotId;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.BooleanMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ByteArrayMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ErrorResponse;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.GetMechanismInfosResponse;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.IntMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.KeyIdMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.LongArrayMessage;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.ModuleCapsResponse;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.P11KeyResponse;
import org.xipki.security.pkcs11.hsmproxy.ProxyMessage.SlotIdsResponse;
import org.xipki.util.Args;
import org.xipki.util.FileOrBinary;
import org.xipki.util.IoUtil;
import org.xipki.util.LogUtil;
import org.xipki.util.StringUtil;
import org.xipki.util.cbor.CborConstants;
import org.xipki.util.cbor.CborDecoder;
import org.xipki.util.cbor.CborType;
import org.xipki.util.exception.DecodeException;
import org.xipki.util.exception.ObjectCreationException;
import org.xipki.util.http.HostnameVerifiers;
import org.xipki.util.http.SslConf;
import org.xipki.util.http.SslContextConf;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSocketFactory;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;

/**
 * {@link P11Module} for PKCS#11 proxy.
 *
 * @author Lijun Liao (xipki)
 */

class HsmProxyP11Module extends P11Module {

  public static final String TYPE = "hsmproxy";

  private static final String PROP_SSL_STORETYPE = "ssl.storeType";

  private static final String PROP_SSL_KEYSTORE = "ssl.keystore";

  private static final String PROP_SSL_KEYSTOREPASSWORD = "ssl.keystorePassword";

  private static final String PROP_SSL_TRUSTCERTS = "ssl.trustcerts";

  private static final String PROP_SSL_HOStNAMEVERIFIER = "ssl.hostnameVerifier";

  private static final Logger LOG = LoggerFactory.getLogger(HsmProxyP11Module.class);

  private static final String REQUEST_MIMETYPE = "application/x-xipki-pkcs11";

  private static final String RESPONSE_MIMETYPE = "application/x-xipki-pkcs11";

  private static final byte[] SLOT_ID_NULL_CONTENT_NULL_REQUEST = new byte[]{(byte) 0x82, (byte) 0xf6, (byte) 0xf6};

  private final String description;

  private final String serverUrl;

  private final SSLSocketFactory sslSocketFactory;

  private final HostnameVerifier hostnameVerifier;

  private HsmProxyP11Module(P11ModuleConf moduleConf) throws TokenException {
    super(moduleConf);

    final String modulePath = moduleConf.getNativeLibrary();

    Map<String, String> properties = moduleConf.getNativeLibraryProperties();
    if (properties == null) {
      throw new TokenException("The properties field is not present");
    }
    this.description = StringUtil.concat("PKCS#11 proxy", "\nPath: ", modulePath);
    this.serverUrl = modulePath.endsWith("/") ? modulePath.substring(0, modulePath.length() - 1) : modulePath;

    SslConf sslConf = new SslConf();

    String sslStoreType = properties.get(PROP_SSL_STORETYPE);
    sslConf.setStoreType(sslStoreType);

    String sslKeystore = properties.get(PROP_SSL_KEYSTORE);
    sslConf.setKeystore(FileOrBinary.ofFile(sslKeystore));

    String sslKeystorePassword = properties.get(PROP_SSL_KEYSTOREPASSWORD);
    sslConf.setKeystorePassword(sslKeystorePassword);

    String sslTrustCerts = properties.get(PROP_SSL_TRUSTCERTS);
    if (sslTrustCerts != null) {
      StringTokenizer tokens = new StringTokenizer(sslTrustCerts, ",;:");
      List<FileOrBinary> files = new ArrayList<>(tokens.countTokens());
      while (tokens.hasMoreTokens()) {
        String file = tokens.nextToken().trim();
        files.add(FileOrBinary.ofFile(file));
      }
      sslConf.setTrustanchors(files.toArray(new FileOrBinary[0]));
    }

    String sslHostnameVerifier = properties.get(PROP_SSL_HOStNAMEVERIFIER);
    if (sslHostnameVerifier != null) {
      sslConf.setHostnameVerifier(sslHostnameVerifier);
    }

    SslContextConf sslContextConf = SslContextConf.ofSslConf(sslConf);

    try {
      this.sslSocketFactory = sslContextConf.getSslSocketFactory();
    } catch (ObjectCreationException ex) {
      throw new TokenException("could not build SSLSocketFactroy", ex);
    }
    try {
      this.hostnameVerifier = HostnameVerifiers.createHostnameVerifier(sslHostnameVerifier);
    } catch (ObjectCreationException ex) {
      throw new TokenException("could not create HostnameVerifier", ex);
    }

    ModuleCapsResponse moduleCaps =
        (ModuleCapsResponse) sendModuleAction(ProxyAction.moduleCaps);
    if (!moduleConf.isReadOnly()) {
      moduleConf.setReadOnly(moduleCaps.isReadOnly());
    }

    if (moduleConf.getMaxMessageSize() > moduleCaps.getMaxMessageSize()) {
      moduleConf.setMaxMessageSize(moduleCaps.getMaxMessageSize());
    }

    if (moduleCaps.getNewObjectConf() != null) {
      moduleConf.setNewObjectConf(moduleCaps.getNewObjectConf());
    }

    if (moduleCaps.getSecretKeyTypes() != null) {
      moduleConf.setSecretKeyTypes(
          intersect(moduleConf.getSecretKeyTypes(), moduleCaps.getSecretKeyTypes()));
    }

    if (moduleCaps.getKeyPairTypes() != null) {
      moduleConf.setKeyPairTypes(
          intersect(moduleConf.getKeyPairTypes(), moduleCaps.getKeyPairTypes()));
    }

    // initialize the slots
    SlotIdsResponse resp = (SlotIdsResponse) sendModuleAction(ProxyAction.slotIds);
    Set<P11Slot> slots = new HashSet<>();
    for (P11SlotId slotId : resp.getSlotIds() ) {
      if (!conf.isSlotIncluded(slotId)) {
        continue;
      }

      if (!conf.isSlotIncluded(slotId)) {
        LOG.info("skipped slot {}", slotId);
        continue;
      }

      HsmProxyP11Slot slot = new HsmProxyP11Slot(slotId, moduleConf.isReadOnly(), this,
          conf.getP11MechanismFilter(), moduleCaps.getNewObjectConf(),
          moduleCaps.getSecretKeyTypes(), moduleCaps.getKeyPairTypes());
      slots.add(slot);
    }
    setSlots(slots);
  } // constructor

  private static <T> List<T> intersect(List<T> a, List<T> b) {
    if (a == null) {
      return b;
    } else if (b == null) {
      return a;
    }

    if (new HashSet<>(a).containsAll(b) && a.size() == b.size()) {
      return a;
    }

    List<T> r = new ArrayList<>(Math.min(a.size(), b.size()));
    for (T ta : a) {
      if (b.contains(ta)) {
        r.add(ta);
      }
    }
    return r;
  }

  public static P11Module getInstance(P11ModuleConf moduleConf) throws TokenException {
    Args.notNull(moduleConf, "moduleConf");
    if (moduleConf.getUserName() != null) {
      throw new TokenException("userName is present but shall be null");
    }

    return new HsmProxyP11Module(moduleConf);
  }

  @Override
  public String getDescription() {
    return description;
  }

  @Override
  public void close() {
    for (P11SlotId slotId : getSlotIds()) {
      try {
        getSlot(slotId).close();
      } catch (Throwable th) {
        LogUtil.error(LOG, th, "could not close PKCS#11 slot " + slotId);
      }
    }
  }

  protected byte[] doSend(ProxyAction action, byte[] request) throws IOException {
    Args.notNull(request, "request");

    String thisUrl = serverUrl + "/" + action.getAlias();

    HttpURLConnection httpUrlConnection = IoUtil.openHttpConn(new URL(thisUrl));

    if (httpUrlConnection instanceof HttpsURLConnection) {
      if (sslSocketFactory != null) {
        ((HttpsURLConnection) httpUrlConnection).setSSLSocketFactory(sslSocketFactory);
      }

      if (hostnameVerifier != null) {
        ((HttpsURLConnection) httpUrlConnection).setHostnameVerifier(hostnameVerifier);
      }
    }

    httpUrlConnection.setDoOutput(true);
    httpUrlConnection.setUseCaches(false);

    int size = request.length;

    httpUrlConnection.setRequestMethod("POST");
    httpUrlConnection.setRequestProperty("Content-Type", REQUEST_MIMETYPE);
    httpUrlConnection.setRequestProperty("Content-Length", Integer.toString(size));
    OutputStream outputstream = httpUrlConnection.getOutputStream();
    outputstream.write(request);
    outputstream.flush();

    if (httpUrlConnection.getResponseCode() != HttpURLConnection.HTTP_OK) {
      try {
        try {
          InputStream is = httpUrlConnection.getInputStream();
          if (is != null) {
            is.close();
          }
        } catch (IOException ex) {
          InputStream errStream = httpUrlConnection.getErrorStream();
          if (errStream != null) {
            errStream.close();
          }
        }
      } catch (Throwable th) {
        // ignore it
      }

      throw new IOException("bad response: code=" + httpUrlConnection.getResponseCode()
          + ", message=" + httpUrlConnection.getResponseMessage());
    }

    InputStream inputstream;
    try {
      inputstream = httpUrlConnection.getInputStream();
    } catch (IOException ex) {
      InputStream errStream = httpUrlConnection.getErrorStream();
      if (errStream != null) {
        errStream.close();
      }
      throw ex;
    }

    try {
      String responseContentType = httpUrlConnection.getContentType();
      boolean isValidContentType = false;
      if (responseContentType != null) {
        if (responseContentType.equalsIgnoreCase(RESPONSE_MIMETYPE)) {
          isValidContentType = true;
        }
      }
      if (!isValidContentType) {
        throw new IOException("bad response: mime type " + responseContentType
            + " is not supported!");
      }

      byte[] buf = new byte[4096];
      ByteArrayOutputStream bytearrayoutputstream = new ByteArrayOutputStream();
      do {
        int readedByte = inputstream.read(buf);
        if (readedByte == -1) {
          break;
        }
        bytearrayoutputstream.write(buf, 0, readedByte);
      } while (true);

      return bytearrayoutputstream.toByteArray();
    } finally {
      inputstream.close();
    }
  } // method send

  public ProxyMessage sendModuleAction(ProxyAction action) throws TokenException {
    return send(action, SLOT_ID_NULL_CONTENT_NULL_REQUEST.clone());
  }

  public ProxyMessage send(ProxyAction action, byte[] request) throws TokenException {
    Args.notNull(request, "request");

    byte[] respBytes;
    try {
      respBytes = doSend(action, request);
    } catch (IOException ex) {
      LOG.error("IO error", request);
      throw new TokenException(ex.getMessage(), ex);
    }

    CborDecoder decoder = new CborDecoder(respBytes);
    ErrorResponse errorResp = null;

    try {
      CborType type = decoder.peekType();
      if (CborDecoder.isNull(type)) {
        decoder.readNull();
        return null;
      } else if (type.getMajorType() == CborConstants.TYPE_TAG) {
        long tag = decoder.readTag();
        if (ErrorResponse.CBOR_TAG_ERROR_RESPONSE != tag) {
          throw new TokenException("response is tagged but not with tag CBOR_TAG_ERROR_RESPONSE");
        }

        errorResp = ErrorResponse.decode(decoder);
      }
    } catch (IOException ex) {
      throw new TokenException("IO error decoding response", ex);
    } catch (DecodeException ex) {
      throw new TokenException("DecodeException decoding response", ex);
    }

    if (errorResp != null) {
      ErrorResponse.ProxyErrorCode errorCode = errorResp.getErrorCode();
      String detail = errorResp.getDetail();

      switch (errorCode) {
        case badRequest:
        case internalError:
          throw new TokenException(errorCode + ": " + detail);
        case pkcs11Exception:
          long ckrCode;
          try {
            ckrCode = detail.startsWith("CKR_") || detail.startsWith("ckr_")
                ? PKCS11Constants.ckrNameToCode(detail) : Long.parseLong(detail);
          } catch (Exception ex) {
            LOG.warn("could not parse CKR code '" + detail + "'");
            ckrCode = PKCS11Constants.CKR_GENERAL_ERROR;
          }
          throw new PKCS11Exception(ckrCode);
        case tokenException:
          throw new TokenException(detail);
      }
    }

    try {
      switch (action) {
        case moduleCaps:
          return ModuleCapsResponse.decode(decoder);
        case slotIds:
          return SlotIdsResponse.decode(decoder);
        case mechInfos:
          return GetMechanismInfosResponse.decode(decoder);
        case keyByKeyId:
        case keyByIdLabel:
          return P11KeyResponse.decode(decoder);
        case objectExistsByIdLabel:
          return BooleanMessage.decode(decoder);
        case destroyAllObjects:
        case destroyObjectsByIdLabel:
          return IntMessage.decode(decoder);
        case destroyObjectsByHandle:
          return LongArrayMessage.decode(decoder);
        case keyIdByIdLabel:
        case genSecretKey:
        case importSecretKey:
        case genRSAKeypair:
        case genDSAKeypair2:
        case genDSAKeypair:
        case genECKeypair:
        case genSM2Keypair:
          return KeyIdMessage.decode(decoder);
        case genRSAKeypairOtf:
        case genDSAKeypairOtf:
        case genECKeypairOtf:
        case genSM2KeypairOtf:
        case publicKeyByHandle:
        case showDetails:
        case sign:
        case digestSecretKey:
          return ByteArrayMessage.decode(decoder);
        default:
          throw new IllegalStateException("should not reach here, unknown action " + action);
      }
    } catch (DecodeException ex) {
      throw new TokenException("DecodingException while decoding response.", ex);
    }
  }

}
