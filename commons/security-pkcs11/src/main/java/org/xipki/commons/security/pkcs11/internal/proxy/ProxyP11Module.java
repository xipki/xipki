/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013 - 2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
 *
 * FOR ANY PART OF THE COVERED WORK IN WHICH THE COPYRIGHT IS OWNED BY
 * THE AUTHOR LIJUN LIAO. LIJUN LIAO DISCLAIMS THE WARRANTY OF NON INFRINGEMENT
 * OF THIRD PARTY RIGHTS.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * The interactive user interfaces in modified source and object code versions
 * of this program must display Appropriate Legal Notices, as required under
 * Section 5 of the GNU Affero General Public License.
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial activities involving the XiPKI software without
 * disclosing the source code of your own applications.
 *
 * For more information, please contact Lijun Liao at this
 * address: lijun.liao@gmail.com
 */

package org.xipki.commons.security.pkcs11.internal.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.GenMsgContent;
import org.bouncycastle.asn1.cmp.GenRepContent;
import org.bouncycastle.asn1.cmp.InfoTypeAndValue;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.cert.cmp.GeneralPKIMessage;
import org.bouncycastle.util.encoders.Hex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.pkcs11proxy.common.Asn1P11SlotIdentifier;
import org.xipki.commons.pkcs11proxy.common.Asn1Util;
import org.xipki.commons.pkcs11proxy.common.P11ProxyConstants;
import org.xipki.commons.pkcs11proxy.common.ServerCaps;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.exception.BadAsn1ObjectException;
import org.xipki.commons.security.api.exception.P11DuplicateEntityException;
import org.xipki.commons.security.api.exception.P11UnknownEntityException;
import org.xipki.commons.security.api.exception.P11UnsupportedMechanismException;
import org.xipki.commons.security.api.p11.AbstractP11Module;
import org.xipki.commons.security.api.p11.P11Module;
import org.xipki.commons.security.api.p11.P11ModuleConf;
import org.xipki.commons.security.api.p11.P11Slot;
import org.xipki.commons.security.api.p11.P11SlotIdentifier;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.util.CmpFailureUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ProxyP11Module extends AbstractP11Module {

    public static final String PREFIX = "proxy:";

    private static final Logger LOG = LoggerFactory.getLogger(ProxyP11Module.class);

    private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";

    private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

    private final GeneralName sender = P11ProxyConstants.REMOTE_P11_CMP_CLIENT;

    private final GeneralName recipient = P11ProxyConstants.REMOTE_P11_CMP_SERVER;

    private final Random random = new Random();

    private int version;

    private URL serverUrl;

    private URL getCapsUrl;

    private boolean readOnly;

    private ProxyP11Module(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        super(moduleConf);

        final String modulePath = moduleConf.getNativeLibrary();
        if (!StringUtil.startsWithIgnoreCase(modulePath, PREFIX)) {
            throw new IllegalArgumentException("the module path does not starts with " + PREFIX
                    + ": " + modulePath);
        }

        ConfPairs confPairs = new ConfPairs(modulePath.substring(PREFIX.length()));
        String urlStr = confPairs.getValue("url");
        try {
            serverUrl = new URL(urlStr);
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("invalid url: " + urlStr);
        }

        urlStr = urlStr + "?operation=GetCaps";
        try {
            getCapsUrl = new URL(urlStr);
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("invalid url: " + urlStr);
        }
        refresh();
    }

    public static P11Module getInstance(
            final P11ModuleConf moduleConf)
    throws P11TokenException {
        ParamUtil.requireNonNull("moduleConf", moduleConf);
        return new ProxyP11Module(moduleConf);
    }

    @Override
    public boolean isReadOnly() {
        return readOnly || super.isReadOnly();
    }

    void refresh()
    throws P11TokenException {
        ServerCaps caps = getServerCaps();
        if (caps.getVersions().contains(1)) {
            version = 1;
        } else {
            throw new P11TokenException(
                    "Server does not support any version supported by the client");
        }
        this.readOnly = caps.isReadOnly();

        ASN1Encodable resp = send(P11ProxyConstants.ACTION_getSlotIds, null);
        if (!(resp instanceof ASN1Sequence)) {
            throw new P11TokenException("response is not ASN1Sequence, but "
                    + resp.getClass().getName());
        }

        ASN1Sequence seq = (ASN1Sequence) resp;
        final int n = seq.size();

        Set<P11Slot> slots = new HashSet<>();
        for (int i = 0; i < n; i++) {
            Asn1P11SlotIdentifier asn1SlotId;
            try {
                ASN1Encodable obj = seq.getObjectAt(i);
                asn1SlotId = Asn1P11SlotIdentifier.getInstance(obj);
            } catch (Exception ex) {
                throw new P11TokenException(ex.getMessage(), ex);
            }

            P11SlotIdentifier slotId = asn1SlotId.getSlotId();
            if (!conf.isSlotIncluded(slotId)) {
                continue;
            }

            if (!conf.isSlotIncluded(slotId)) {
                LOG.info("skipped slot {}", slotId);
                continue;
            }

            P11Slot slot = new ProxyP11Slot(this, slotId, conf.isReadOnly(),
                    conf.getP11MechanismFilter());
            slots.add(slot);
        }
        setSlots(slots);
    }

    @Override
    public void close() {
        for (P11SlotIdentifier slotId : getSlotIdentifiers()) {
            try {
                getSlot(slotId).close();
            } catch (Throwable th) {
                LogUtil.error(LOG, th, "could not close PKCS#11 slot " + slotId);
            }
        }
    }

    byte[] send(
            final byte[] request)
    throws IOException {
        ParamUtil.requireNonNull("request", request);
        HttpURLConnection httpUrlConnection = (HttpURLConnection) serverUrl.openConnection();
        httpUrlConnection.setDoOutput(true);
        httpUrlConnection.setUseCaches(false);

        int size = request.length;

        httpUrlConnection.setRequestMethod("POST");
        httpUrlConnection.setRequestProperty("Content-Type", CMP_REQUEST_MIMETYPE);
        httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
        OutputStream outputstream = httpUrlConnection.getOutputStream();
        outputstream.write(request);
        outputstream.flush();

        InputStream inputstream = null;
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
                if (responseContentType.equalsIgnoreCase(CMP_RESPONSE_MIMETYPE)) {
                    isValidContentType = true;
                }
            }
            if (!isValidContentType) {
                throw new IOException("bad response: mime type "
                        + responseContentType
                        + " not supported!");
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

    ASN1Encodable send(
            final int action,
            final ASN1Encodable content)
    throws P11TokenException {
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(version));
        vec.add(new ASN1Integer(action));
        if (content != null) {
            vec.add(content);
        } else {
            vec.add(DERNull.INSTANCE);
        }
        InfoTypeAndValue itvReq = new InfoTypeAndValue(ObjectIdentifiers.id_xipki_cmp_cmpGenmsg,
                new DERSequence(vec));

        GenMsgContent genMsgContent = new GenMsgContent(itvReq);
        PKIHeader header = buildPkiHeader(null);
        PKIBody body = new PKIBody(PKIBody.TYPE_GEN_MSG, genMsgContent);
        PKIMessage request = new PKIMessage(header, body);

        byte[] encodedRequest;
        try {
            encodedRequest = request.getEncoded();
        } catch (IOException ex) {
            final String msg = "could not encode the PKI request";
            LOG.error(msg + " {}", request);
            throw new P11TokenException(msg + ": " + ex.getMessage(), ex);
        }

        byte[] encodedResponse;
        try {
            encodedResponse = send(encodedRequest);
        } catch (IOException ex) {
            final String msg = "could not send the PKI request";
            LOG.error(msg + " {}", request);
            throw new P11TokenException(msg + ": " + ex.getMessage(), ex);
        }

        GeneralPKIMessage response;
        try {
            response = new GeneralPKIMessage(encodedResponse);
        } catch (IOException ex) {
            final String msg = "could not decode the received PKI message";
            LOG.error(msg + ": {}",
                    Hex.toHexString(encodedResponse));
            throw new P11TokenException(msg + ": " + ex.getMessage(), ex);
        }

        PKIHeader respHeader = response.getHeader();
        ASN1OctetString tid = respHeader.getTransactionID();
        GeneralName rec = respHeader.getRecipient();
        if (!sender.equals(rec)) {
            LOG.warn("tid={}: unknown CMP requestor '{}'", tid, rec);
        }

        return extractItvInfoValue(action, response);
    } // method send

    private PKIHeader buildPkiHeader(
            final ASN1OctetString tid) {
        PKIHeaderBuilder hdrBuilder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                sender,
                recipient);
        hdrBuilder.setMessageTime(new ASN1GeneralizedTime(new Date()));

        ASN1OctetString tmpTid;
        if (tid == null) {
            tmpTid = new DEROctetString(randomTransactionId());
        } else {
            tmpTid = tid;
        }
        hdrBuilder.setTransactionID(tmpTid);

        return hdrBuilder.build();
    }

    private byte[] randomTransactionId() {
        byte[] tid = new byte[20];
        synchronized (random) {
            random.nextBytes(tid);
        }
        return tid;
    }

    private ServerCaps getServerCaps()
    throws P11TokenException {
        byte[] respBytes;
        try {
            HttpURLConnection conn = (HttpURLConnection) getCapsUrl.openConnection();
            conn.setRequestMethod("GET");
            checkResponseCode(conn);
            InputStream respStream = conn.getInputStream();
            respBytes = IoUtil.read(respStream);
        } catch (IOException ex) {
            throw new P11TokenException(ex.getMessage(), ex);
        }

        return new ServerCaps(respBytes);
    }

    private ASN1Encodable extractItvInfoValue(
            final int action,
            final GeneralPKIMessage response)
    throws P11TokenException {
        PKIBody respBody = response.getBody();
        int bodyType = respBody.getType();

        if (PKIBody.TYPE_ERROR == bodyType) {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            PKIStatusInfo statusInfo = content.getPKIStatusInfo();
            String failureInfo = null;
            if (statusInfo.getStatusString() != null) {
                int size = statusInfo.getStatusString().size();
                if (size > 0) {
                    failureInfo = statusInfo.getStatusString().getStringAt(0).getString();
                }
            }

            if (failureInfo == null) {
                throw new P11TokenException("server answered with ERROR: "
                        + CmpFailureUtil.formatPkiStatusInfo(statusInfo));
            }

            if (failureInfo.startsWith(P11ProxyConstants.ERROR_P11_TOKENERROR)) {
                ConfPairs pairs = new ConfPairs(failureInfo);
                String errorMesage = pairs.getValue(P11ProxyConstants.ERROR_P11_TOKENERROR);
                throw new P11TokenException(errorMesage);
            } else if (failureInfo.startsWith(P11ProxyConstants.ERROR_UNKNOWN_ENTITY)) {
                ConfPairs pairs = new ConfPairs(failureInfo);
                String errorMesage = pairs.getValue(P11ProxyConstants.ERROR_UNKNOWN_ENTITY);
                throw new P11UnknownEntityException(errorMesage);
            } else if (failureInfo.startsWith(P11ProxyConstants.ERROR_UNSUPPORTED_MECHANISM)) {
                ConfPairs pairs = new ConfPairs(failureInfo);
                String errorMesage = pairs.getValue(P11ProxyConstants.ERROR_UNSUPPORTED_MECHANISM);
                throw new P11UnsupportedMechanismException(errorMesage);
            } else if (failureInfo.startsWith(P11ProxyConstants.ERROR_DUPLICATE_ENTITY)) {
                ConfPairs pairs = new ConfPairs(failureInfo);
                String errorMesage = pairs.getValue(P11ProxyConstants.ERROR_UNSUPPORTED_MECHANISM);
                throw new P11DuplicateEntityException(errorMesage);
            } else {
                throw new P11TokenException("server answered with ERROR: "
                        + CmpFailureUtil.formatPkiStatusInfo(statusInfo));
            }
        } else if (PKIBody.TYPE_GEN_REP != bodyType) {
            throw new P11TokenException("unknown PKI body type " + bodyType
                    + " instead the exceptected [" + PKIBody.TYPE_GEN_REP + ", "
                    + PKIBody.TYPE_ERROR + "]");
        }

        GenRepContent genRep = (GenRepContent) respBody.getContent();

        InfoTypeAndValue[] itvs = genRep.toInfoTypeAndValueArray();
        InfoTypeAndValue itv = null;
        if (itvs != null && itvs.length > 0) {
            for (InfoTypeAndValue m : itvs) {
                if (ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.equals(m.getInfoType())) {
                    itv = m;
                    break;
                }
            }
        }
        if (itv == null) {
            throw new P11TokenException("the response does not contain InfoTypeAndValue '"
                    + ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId() + "'");
        }

        ASN1Encodable itvValue = itv.getInfoValue();
        if (itvValue == null) {
            throw new P11TokenException("value of InfoTypeAndValue '"
                    + ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId() + "' is incorrect");
        }

        try {
            ASN1Sequence seq = Asn1Util.getSequence(itvValue);
            Asn1Util.requireRange(seq, 2, 3);

            int receivedversion = Asn1Util.getInteger(seq.getObjectAt(0)).intValue();
            if (receivedversion != version) {
                throw new P11TokenException("version '"
                        + receivedversion + "' is not the expected '" + version + "'");
            }

            int receivedAction = Asn1Util.getInteger(seq.getObjectAt(1)).intValue();
            if (receivedAction != action) {
                throw new P11TokenException("action '"
                        + receivedAction + "' is not the expected '" + action + "'");
            }

            if (seq.size() > 2) {
                return seq.getObjectAt(2);
            } else {
                return null;
            }
        } catch (BadAsn1ObjectException ex) {
            throw new P11TokenException("bad ASN1 object: " + ex.getMessage(), ex);
        }
    } // method extractItvInfoValue

    private void checkResponseCode(
            final HttpURLConnection conn)
    throws P11TokenException {
        ParamUtil.requireNonNull("conn", conn);
        try {
            if (conn.getResponseCode() != HttpURLConnection.HTTP_OK) {
                conn.getInputStream().close();
                throw new P11TokenException("bad response: code=" + conn.getResponseCode()
                        + ", message=" + conn.getResponseMessage());
            }
        } catch (IOException ex) {
            throw new P11TokenException("IOException: " + ex.getMessage(), ex);
        }
    }
}
