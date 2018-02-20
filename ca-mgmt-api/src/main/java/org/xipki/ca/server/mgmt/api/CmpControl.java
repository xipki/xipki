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

package org.xipki.ca.server.mgmt.api;

import java.security.NoSuchAlgorithmException;
import java.util.Set;

import org.xipki.common.ConfPairs;
import org.xipki.common.InvalidConfException;
import org.xipki.common.util.CollectionUtil;
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

    public static final String KEY_MESSAGETIME_REQUIRED = "messagetime.required";

    public static final String KEY_MESSAGETIME_BIAS = "messagetime.bias";

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

    public CmpControl(CmpControlEntry dbEntry) throws InvalidConfException {
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
        Set<String> algos = (str == null) ? null : splitAlgos(str);
        try {
            this.sigAlgoValidator = new CollectionAlgorithmValidator(algos);
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidConfException("invalid " + KEY_PROTECTION_SIGALGO + ": " + str, ex);
        }
        algos = this.sigAlgoValidator.algoNames();
        pairs.putPair(KEY_PROTECTION_SIGALGO, algosAsString(algos));

        // popo algorithms
        str = pairs.value(KEY_POPO_SIGALGO);
        algos = (str == null) ? null : splitAlgos(str);
        try {
            this.popoAlgoValidator = new CollectionAlgorithmValidator(algos);
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidConfException("invalid " + KEY_POPO_SIGALGO + ": " + str, ex);
        }
        algos = this.popoAlgoValidator.algoNames();
        pairs.putPair(KEY_POPO_SIGALGO, algosAsString(algos));

        this.dbEntry = new CmpControlEntry(dbEntry.name(), pairs.getEncoded());
    } // constructor

    public CmpControl(String name, Boolean confirmCert, Boolean sendCaCert,
            Boolean messageTimeRequired, Boolean sendResponderCert, Boolean rrAkiRequired,
            Integer messageTimeBias, Integer confirmWaitTime, Boolean groupEnroll,
            Set<String> sigAlgos, Set<String> popoAlgos) throws InvalidConfException {
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

        if (CollectionUtil.isNonEmpty(sigAlgos)) {
            pairs.putPair(KEY_PROTECTION_SIGALGO, algosAsString(this.sigAlgoValidator.algoNames()));
        }

        try {
            this.popoAlgoValidator = new CollectionAlgorithmValidator(popoAlgos);
        } catch (NoSuchAlgorithmException ex) {
            throw new InvalidConfException("invalid popoAlgos", ex);
        }

        if (CollectionUtil.isNonEmpty(popoAlgos)) {
            pairs.putPair(KEY_POPO_SIGALGO, algosAsString(this.popoAlgoValidator.algoNames()));
        }

        this.dbEntry = new CmpControlEntry(name, pairs.getEncoded());
    } // constructor

    public boolean messageTimeRequired() {
        return messageTimeRequired;
    }

    public boolean confirmCert() {
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

    public boolean sendCaCert() {
        return sendCaCert;
    }

    public boolean rrAkiRequired() {
        return rrAkiRequired;
    }

    public boolean sendResponderCert() {
        return sendResponderCert;
    }

    public boolean groupEnroll() {
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
        String protAlgos = algosAsString(sigAlgoValidator.algoNames());
        String popoAlgos = algosAsString(popoAlgoValidator.algoNames());
        return StringUtil.concatObjectsCap(500, "name: ", dbEntry.name(),
                "\nconfirmCert: ", getYesNo(confirmCert),
                "\nsendCaCert: ", getYesNo(sendCaCert),
                "\nsendResponderCert: ", getYesNo(sendResponderCert),
                "\nmessageTimeRequired: ", getYesNo(messageTimeRequired),
                "\ngroupEnroll: ", getYesNo(groupEnroll),
                "\nmessageTimeBias: ", messageTimeBias, " s",
                "\nconfirmWaitTime: ", confirmWaitTime, " s",
                "\nprotection algos: ", protAlgos,
                "\npopo algos: ",  popoAlgos, "conf: ", dbEntry.conf());
    }

    private static boolean getBoolean(ConfPairs pairs, String key, boolean defaultValue) {
        String str = pairs.value(key);
        boolean ret = StringUtil.isBlank(str) ? defaultValue : Boolean.parseBoolean(str);
        pairs.putPair(key, Boolean.toString(ret));
        return ret;
    }

    private static int getInt(ConfPairs pairs, String key, int defaultValue) {
        String str = pairs.value(key);
        int ret = StringUtil.isBlank(str) ? defaultValue : Integer.parseInt(str);
        pairs.putPair(key, Integer.toString(ret));
        return ret;
    }

    private static String getYesNo(boolean bo) {
        return bo ? "yes" : "no";
    }

    private static String algosAsString(Set<String> algos) {
        return StringUtil.collectionAsString(algos, ALGO_DELIMITER);
    }

    private static Set<String> splitAlgos(String encoded) {
        return StringUtil.splitAsSet(encoded, ALGO_DELIMITER);
    }

}
