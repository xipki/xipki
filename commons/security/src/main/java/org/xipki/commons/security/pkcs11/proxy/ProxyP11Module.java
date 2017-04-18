/*
 *
 * Copyright (c) 2013 - 2017 Lijun Liao
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

package org.xipki.commons.security.pkcs11.proxy;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashSet;
import java.util.Random;
import java.util.Set;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Sequence;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xipki.commons.common.ConfPairs;
import org.xipki.commons.common.util.IoUtil;
import org.xipki.commons.common.util.LogUtil;
import org.xipki.commons.common.util.ParamUtil;
import org.xipki.commons.common.util.StringUtil;
import org.xipki.commons.security.exception.BadAsn1ObjectException;
import org.xipki.commons.security.exception.P11TokenException;
import org.xipki.commons.security.pkcs11.AbstractP11Module;
import org.xipki.commons.security.pkcs11.P11Module;
import org.xipki.commons.security.pkcs11.P11ModuleConf;
import org.xipki.commons.security.pkcs11.P11Slot;
import org.xipki.commons.security.pkcs11.P11SlotIdentifier;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1P11SlotIdentifier;
import org.xipki.commons.security.pkcs11.proxy.msg.Asn1ServerCaps;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class ProxyP11Module extends AbstractP11Module {

    public static final String PREFIX = "proxy:";

    private static final Logger LOG = LoggerFactory.getLogger(ProxyP11Module.class);

    private static final String REQUEST_MIMETYPE = "application/x-xipki-pkcs11";

    private static final String RESPONSE_MIMETYPE = "application/x-xipki-pkcs11";

    private final Random random = new Random();

    private final short version = P11ProxyConstants.VERSION_V1_0;

    private URL serverUrl;

    private short moduleId;

    private boolean readOnly;

    private ProxyP11Module(final P11ModuleConf moduleConf) throws P11TokenException {
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

        String moduleStr = confPairs.getValue("module");
        if (moduleStr == null) {
            throw new IllegalArgumentException("module not specified");
        }

        try {
            moduleStr = moduleStr.trim();
            if (moduleStr.startsWith("0x") || moduleStr.startsWith("0X")) {
                moduleId = Short.parseShort(moduleStr.substring(2), 16);
            } else {
                moduleId = Short.parseShort(moduleStr.trim());
            }
        } catch (NumberFormatException ex) {
            throw new IllegalArgumentException("invalid module: " + moduleStr);
        }

        refresh();
    }

    public static P11Module getInstance(final P11ModuleConf moduleConf) throws P11TokenException {
        ParamUtil.requireNonNull("moduleConf", moduleConf);
        return new ProxyP11Module(moduleConf);
    }

    @Override
    public boolean isReadOnly() {
        return readOnly || super.isReadOnly();
    }

    public void refresh() throws P11TokenException {
        byte[] resp = send(P11ProxyConstants.ACTION_GET_SERVER_CAPS, null);

        Asn1ServerCaps caps;
        try {
            caps = Asn1ServerCaps.getInstance(resp);
        } catch (BadAsn1ObjectException ex) {
            throw new P11TokenException("response is a valid Asn1ServerCaps", ex);
        }

        if (!caps.getVersions().contains(version)) {
            throw new P11TokenException(
                    "Server does not support any version supported by the client");
        }
        this.readOnly = caps.isReadOnly();

        resp = send(P11ProxyConstants.ACTION_GET_SLOT_IDS, null);

        ASN1Sequence seq;
        try {
            seq = ASN1Sequence.getInstance(resp);
        } catch (IllegalArgumentException ex) {
            throw new P11TokenException("response is not ASN1Sequence", ex);
        }

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

    protected byte[] send(final byte[] request) throws IOException {
        ParamUtil.requireNonNull("request", request);
        HttpURLConnection httpUrlConnection = IoUtil.openHttpConn(serverUrl);
        httpUrlConnection.setDoOutput(true);
        httpUrlConnection.setUseCaches(false);

        int size = request.length;

        httpUrlConnection.setRequestMethod("POST");
        httpUrlConnection.setRequestProperty("Content-Type", REQUEST_MIMETYPE);
        httpUrlConnection.setRequestProperty("Content-Length", java.lang.Integer.toString(size));
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
            }
            while (true);

            return bytearrayoutputstream.toByteArray();
        } finally {
            inputstream.close();
        }
    } // method send

    /**
     * The request is constructed as follows:
     * <pre>
     * 0 - - - 1 - - - 2 - - - 3 - - - 4 - - - 5 - - - 6 - - - 7 - - - 8
     * |    Version    |        Transaction ID         |   Body ...    |
     * |   ... Length  |     Action    |   Module ID   |   Content...  |
     * |   .Content               | <-- 10 + Length (offset).
     *
     * </pre>
     * @param action action
     * @param content content
     * @return result.
     * @throws P11TokenException If error occurred.
     */
    public byte[] send(final short action, final ASN1Object content)
            throws P11TokenException {
        byte[] encodedContent;
        if (content == null) {
            encodedContent = null;
        } else {
            try {
                encodedContent = content.getEncoded();
            } catch (IOException ex) {
                throw new P11TokenException("could encode the content", ex);
            }
        }

        int bodyLen = 4;
        if (encodedContent != null) {
            bodyLen += encodedContent.length;
        }

        byte[] request = new byte[10 + bodyLen];

        // version
        IoUtil.writeShort(version, request, 0);

        // transaction id
        byte[] transactionId = randomTransactionId();
        System.arraycopy(transactionId, 0, request, 2, 4);

        // length
        IoUtil.writeInt(bodyLen, request, 6);

        // action
        IoUtil.writeShort(action, request, 10);

        // module ID
        IoUtil.writeShort(moduleId, request, 12);

        //content
        if (encodedContent != null) {
            System.arraycopy(encodedContent, 0, request, 14, encodedContent.length);
        }

        byte[] response;
        try {
            response = send(request);
        } catch (IOException ex) {
            final String msg = "could not send the request";
            LOG.error(msg + " {}", request);
            throw new P11TokenException(msg + ": " + ex.getMessage(), ex);
        }

        int respLen = response.length;
        if (respLen < 12) {
            throw new P11TokenException("response too short");
        }

        // Length
        int respBodyLen = IoUtil.parseInt(response, 6);
        if (respBodyLen + 10 != respLen) {
            throw new P11TokenException("message lengt unmatch");
        }

        // RC
        short rc = IoUtil.parseShort(response, 10);
        if (rc != 0) {
            throw new P11TokenException(
                    "server returned RC " + P11ProxyConstants.getReturnCodeName(rc));
        }

        // Version
        short respVersion = IoUtil.parseShort(response, 0);
        if (version != respVersion) {
            throw new P11TokenException("version of response and request unmatch");
        }

        // TransactionID
        if (!equals(transactionId, response, 2)) {
            throw new P11TokenException("version of response and request unmatch");
        }

        if (respLen < 14) {
            throw new P11TokenException("too short successful response");
        }

        short respAction = IoUtil.parseShort(response, 12);
        if (action != respAction) {
            throw new P11TokenException("action of response and request unmatch");
        }

        int respContentLen = respLen - 14;
        if (respContentLen == 0) {
            return null;
        }

        byte[] respContent = new byte[respContentLen];
        System.arraycopy(response, 14, respContent, 0, respContentLen);
        return respContent;
    } // method send

    private byte[] randomTransactionId() {
        byte[] tid = new byte[4];
        random.nextBytes(tid);
        return tid;
    }

    private static boolean equals(byte[] bytes, byte[] bytesB, int offsetB) {
        if (bytesB.length - offsetB < bytes.length) {
            return false;
        }

        for (int i = 0; i < bytes.length; i++) {
            if (bytes[i] != bytesB[offsetB + i]) {
                return false;
            }
        }
        return true;
    }

}
