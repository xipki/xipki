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

package org.xipki.pki.ca.server.mgmt.api;

import java.security.NoSuchAlgorithmException;
import java.util.Set;

import org.xipki.common.ConfPairs;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.ParamUtil;
import org.xipki.common.util.StringUtil;
import org.xipki.security.AlgorithmValidator;
import org.xipki.security.CollectionAlgorithmValidator;

/**
 * @author Lijun Liao
 * @since 2.0.0
 */

public class CmpControl {

    public static final String ALGO_DELIMITER = ":";

    public static final String KEY_CONFIRM_CERT = "confirm.cert";

    public static final String KEY_SEND_CA = "send.ca";

    public static final String KEY_SEND_RESPONDER = "send.responder";

    public static final String KEY_MESSAGETIME_REQUIRED = "messageTime.required";

    public static final String KEY_MESSAGETIME_BIAS = "messageTime.bias";

    public static final String KEY_CONFIRM_WAITTIME = "confirm.waittime";

    public static final String KEY_PROTECTION_SIGALGO = "protection.sigalgo";

    public static final String KEY_POPO_SIGALGO = "popo.sigalgo";

    public static final String KEY_GROUP_ENROLL = "group.enroll";

    public static final String KEY_RR_AKI_REQUIRED = "rr.aki.required";

    private static final int DFLT_MESSAGE_TIME_BIAS = 300; // 300 seconds

    private static final int DFLT_CONFIRM_WAIT_TIME = 300; // 300 seconds

    private final CmpControlEntry dbEntry;

    private final boolean confirmCert;

    private final boolean sendCaCert;

    private final boolean messageTimeRequired;

    private final boolean sendResponderCert;

    private final int messageTimeBias;

    private final int confirmWaitTime;

    private final long confirmWaitTimeMs;

    private final boolean groupEnroll;

    private final boolean rrAkiRequired;

    private final CollectionAlgorithmValidator sigAlgoValidator;

    private final CollectionAlgorithmValidator popoAlgoValidator;

    public CmpControl(final CmpControlEntry dbEntry) throws InvalidConfException {
        ParamUtil.requireNonNull("dbEntry", dbEntry);

        ConfPairs pairs = new ConfPairs(dbEntry.conf());
        this.confirmCert = getBoolean(pairs, KEY_CONFIRM_CERT, false);
        this.sendCaCert = getBoolean(pairs, KEY_SEND_CA, false);
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
        String str = pairs.value(KEY_PROTECTION_SIGALGO);
        Set<String> algos = (str == null) ? null : StringUtil.splitAsSet(str, ALGO_DELIMITER);
        try {
            this.sigAlgoValidator = new CollectionAlgorithmValidator(algos);
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidConfException("invalid " + KEY_PROTECTION_SIGALGO + ": " + str, ex);
        }
        algos = this.sigAlgoValidator.algoNames();
        pairs.putPair(KEY_PROTECTION_SIGALGO, StringUtil.collectionAsString(algos, ALGO_DELIMITER));

        // popo algorithms
        str = pairs.value(KEY_POPO_SIGALGO);
        algos = (str == null) ? null : StringUtil.splitAsSet(str, ALGO_DELIMITER);
        try {
            this.popoAlgoValidator = new CollectionAlgorithmValidator(algos);
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidConfException("invalid " + KEY_POPO_SIGALGO + ": " + str, ex);
        }
        algos = this.popoAlgoValidator.algoNames();
        pairs.putPair(KEY_POPO_SIGALGO, StringUtil.collectionAsString(algos, ALGO_DELIMITER));

        this.dbEntry = new CmpControlEntry(dbEntry.name(), pairs.getEncoded());
    } // constructor

    public CmpControl(final String name, final Boolean confirmCert, final Boolean sendCaCert,
            final Boolean messageTimeRequired, final Boolean sendResponderCert,
            final Boolean rrAkiRequired, final Integer messageTimeBias,
            final Integer confirmWaitTime, final Boolean groupEnroll, final Set<String> sigAlgos,
            final Set<String> popoAlgos) throws InvalidConfException {
        ParamUtil.requireNonBlank("name", name);
        if (confirmWaitTime != null) {
            ParamUtil.requireMin("confirmWaitTime", confirmWaitTime, 0);
        }

        ConfPairs pairs = new ConfPairs();

        this.confirmCert = (confirmCert == null) ? false : confirmCert;
        pairs.putPair(KEY_CONFIRM_CERT, Boolean.toString(this.confirmCert));

        this.sendCaCert = (sendCaCert == null) ? false : sendCaCert;
        pairs.putPair(KEY_SEND_CA, Boolean.toString(this.sendCaCert));

        this.messageTimeRequired = (messageTimeRequired == null) ? true : messageTimeRequired;
        pairs.putPair(KEY_MESSAGETIME_REQUIRED, Boolean.toString(this.messageTimeRequired));

        this.sendResponderCert = (sendResponderCert == null) ? true
                : sendResponderCert.booleanValue();
        pairs.putPair(KEY_SEND_RESPONDER, Boolean.toString(this.sendResponderCert));

        this.rrAkiRequired = (rrAkiRequired == null) ? true : rrAkiRequired.booleanValue();
        pairs.putPair(KEY_RR_AKI_REQUIRED, Boolean.toString(this.rrAkiRequired));

        this.messageTimeBias = (messageTimeBias == null) ? DFLT_MESSAGE_TIME_BIAS : messageTimeBias;
        pairs.putPair(KEY_MESSAGETIME_BIAS, Integer.toString(this.messageTimeBias));

        this.confirmWaitTime = (confirmWaitTime == null) ? DFLT_CONFIRM_WAIT_TIME : confirmWaitTime;
        pairs.putPair(KEY_CONFIRM_WAITTIME, Integer.toString(this.confirmWaitTime));

        this.confirmWaitTimeMs = this.confirmWaitTime * 1000L;

        this.groupEnroll = (groupEnroll == null) ? false : groupEnroll;
        try {
            this.sigAlgoValidator = new CollectionAlgorithmValidator(sigAlgos);
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidConfException("invalid sigAlgos", ex);
        }
        pairs.putPair(KEY_PROTECTION_SIGALGO,
            StringUtil.collectionAsString(this.sigAlgoValidator.algoNames(), ALGO_DELIMITER));

        try {
            this.popoAlgoValidator = new CollectionAlgorithmValidator(popoAlgos);
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidConfException("invalid popoAlgos", ex);
        }
        pairs.putPair(KEY_POPO_SIGALGO,
            StringUtil.collectionAsString(this.popoAlgoValidator.algoNames(), ALGO_DELIMITER));

        this.dbEntry = new CmpControlEntry(name, pairs.getEncoded());
    } // constructor

    public boolean isMessageTimeRequired() {
        return messageTimeRequired;
    }

    public boolean isConfirmCert() {
        return confirmCert;
    }

    public int messageTimeBias() {
        return messageTimeBias;
    }

    public int confirmWaitTime() {
        return confirmWaitTime;
    }

    public long confirmWaitTimeMs() {
        return confirmWaitTimeMs;
    }

    public boolean isSendCaCert() {
        return sendCaCert;
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

    public AlgorithmValidator sigAlgoValidator() {
        return sigAlgoValidator;
    }

    public AlgorithmValidator popoAlgoValidator() {
        return popoAlgoValidator;
    }

    public CmpControlEntry dbEntry() {
        return dbEntry;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder(500);
        sb.append("name: ").append(dbEntry.name()).append('\n');
        sb.append("confirmCert: ").append(getYesNo(confirmCert)).append('\n');
        sb.append("sendCaCert: ").append(getYesNo(sendCaCert)).append("\n");
        sb.append("sendResponderCert: ").append(getYesNo(sendResponderCert)).append("\n");
        sb.append("messageTimeRequired: ").append(getYesNo(messageTimeRequired)).append("\n");
        sb.append("groupEnroll: ").append(getYesNo(groupEnroll)).append("\n");
        sb.append("messageTimeBias: ").append(messageTimeBias).append(" s").append('\n');
        sb.append("confirmWaitTime: ").append(confirmWaitTime).append(" s").append('\n');
        sb.append("signature algos: ")
            .append(StringUtil.collectionAsString(sigAlgoValidator.algoNames(), ALGO_DELIMITER))
            .append('\n');
        sb.append("popo algos: ")
            .append(StringUtil.collectionAsString(popoAlgoValidator.algoNames(), ALGO_DELIMITER))
            .append('\n');
        sb.append("conf: ").append(dbEntry.conf());

        return sb.toString();
    }

    private static boolean getBoolean(final ConfPairs pairs, final String key,
            final boolean defaultValue) {
        String str = pairs.value(key);
        boolean ret = StringUtil.isBlank(str) ? defaultValue : Boolean.parseBoolean(str);
        pairs.putPair(key, Boolean.toString(ret));
        return ret;
    }

    private static int getInt(final ConfPairs pairs, final String key, final int defaultValue) {
        String str = pairs.value(key);
        int ret = StringUtil.isBlank(str) ? defaultValue : Integer.parseInt(str);
        pairs.putPair(key, Integer.toString(ret));
        return ret;
    }

    private static String getYesNo(boolean bo) {
        return bo ? "yes" : "no";
    }

}
