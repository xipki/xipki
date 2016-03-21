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

package org.xipki.commons.pkcs11proxy.client.impl;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.Date;
import java.util.Random;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
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
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.pkcs11proxy.common.P11ProxyConstants;
import org.xipki.commons.security.api.ObjectIdentifiers;
import org.xipki.commons.security.api.p11.P11TokenException;
import org.xipki.commons.security.api.util.CmpFailureUtil;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

class P11Communicator {

    private static final Logger LOG = LoggerFactory.getLogger(P11Communicator.class);

    private static final String CMP_REQUEST_MIMETYPE = "application/pkixcmp";

    private static final String CMP_RESPONSE_MIMETYPE = "application/pkixcmp";

    private final GeneralName sender = P11ProxyConstants.REMOTE_P11_CMP_CLIENT;

    private final GeneralName recipient = P11ProxyConstants.REMOTE_P11_CMP_SERVER;

    private final Random random = new Random();

    private final String serverUrl;

    private URL objServerUrl;

    P11Communicator(
            final String serverUrl) {
        this.serverUrl = ParamUtil.requireNonBlank("serverUrl", serverUrl);
        try {
            objServerUrl = new URL(serverUrl);
        } catch (MalformedURLException ex) {
            throw new IllegalArgumentException("invalid url: " + serverUrl);
        }
    }

    String getServerUrl() {
        return serverUrl;
    }

    byte[] send(
            final byte[] request)
    throws IOException {
        ParamUtil.requireNonNull("request", request);
        HttpURLConnection httpUrlConnection = (HttpURLConnection) objServerUrl.openConnection();
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

    // FIXME: consider the exception PKIError/PKIFailureInfo
    ASN1Encodable send(
            final int action,
            final ASN1Encodable content)
    throws P11TokenException {
        PKIHeader header = buildPkiHeader(null);
        ASN1EncodableVector vec = new ASN1EncodableVector();
        vec.add(new ASN1Integer(action));
        if (content != null) {
            vec.add(content);
        }
        InfoTypeAndValue itvReq = new InfoTypeAndValue(ObjectIdentifiers.id_xipki_cmp_cmpGenmsg,
                new DERSequence(vec));

        GenMsgContent genMsgContent = new GenMsgContent(itvReq);
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

    private static ASN1Encodable extractItvInfoValue(
            final int action,
            final GeneralPKIMessage response)
    throws P11TokenException {
        PKIBody respBody = response.getBody();
        int bodyType = respBody.getType();

        if (PKIBody.TYPE_ERROR == bodyType) {
            ErrorMsgContent content = (ErrorMsgContent) respBody.getContent();
            PKIStatusInfo statusInfo = content.getPKIStatusInfo();
            throw new P11TokenException("server answered with ERROR: "
                    + CmpFailureUtil.formatPkiStatusInfo(statusInfo));
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
            ASN1Sequence seq = ASN1Sequence.getInstance(itvValue);
            int receivedAction = ASN1Integer.getInstance(seq.getObjectAt(0))
                    .getPositiveValue().intValue();
            if (receivedAction != action) {
                throw new P11TokenException("xipki action '"
                        + receivedAction + "' is not the expected '" + action + "'");
            }
            return seq.size() > 1
                    ? seq.getObjectAt(1)
                    : null;
        } catch (IllegalArgumentException | ArrayIndexOutOfBoundsException ex) {
            throw new P11TokenException("value of response (type nfoTypeAndValue) '"
                    + ObjectIdentifiers.id_xipki_cmp_cmpGenmsg.getId() + "' is incorrect");
        }
    } // method extractItvInfoValue

}
