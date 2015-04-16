/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2014 - 2015 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License version 3
 * as published by the Free Software Foundation with the addition of the
 * following permission added to Section 15 as permitted in Section 7(a):
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
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
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

package org.xipki.ca.server.impl;

import java.security.NoSuchAlgorithmException;
import java.util.Set;

import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.xipki.ca.server.mgmt.api.CmpControlEntry;
import org.xipki.common.CmpUtf8Pairs;
import org.xipki.common.ParamChecker;
import org.xipki.common.util.AlgorithmUtil;
import org.xipki.common.util.CollectionUtil;
import org.xipki.common.util.StringUtil;

/**
 * @author Lijun Liao
 */

class CmpControl
{
    public static final String KEY_CONFIRM_CERT = "confirm.cert";
    public static final String KEY_SEND_CA = "send.ca";
    public static final String KEY_SEND_RESPONDER = "send.responder";
    public static final String KEY_MESSAGETIME_REQUIRED = "messageTime.required";
    public static final String KEY_MESSAGETIME_BIAS = "messageTime.bias";
    public static final String KEY_CONFIRM_WAITTIME = "confirm.waittime";
    public static final String KEY_PROTECTION_SIGALGO = "protection.sigalgo";

    private static final int DFLT_messageTimeBias = 300; // 300 seconds
    private static final int DFLT_confirmWaitTime = 300; // 300 seconds

    private final CmpControlEntry dbEntry;
    private final boolean confirmCert;
    private final boolean sendCaCert;

    private final boolean messageTimeRequired;
    private final boolean sendResponderCert;

    private final int messageTimeBias;
    private final int confirmWaitTime;
    private final Set<String> sigAlgos;

    public boolean isMessageTimeRequired()
    {
        return messageTimeRequired;
    }

    public CmpControl(
            final CmpControlEntry dbEntry)
    {
        ParamChecker.assertNotNull("dbEntry", dbEntry);

        CmpUtf8Pairs pairs = new CmpUtf8Pairs(dbEntry.getConf());
        this.confirmCert = getBoolean(pairs, KEY_CONFIRM_CERT, false);
        this.sendCaCert = getBoolean(pairs, KEY_SEND_CA, false);
        this.sendResponderCert = getBoolean(pairs, KEY_SEND_RESPONDER, true);
        this.messageTimeRequired = getBoolean(pairs, KEY_MESSAGETIME_REQUIRED, true);
        this.messageTimeBias = getInt(pairs, KEY_MESSAGETIME_BIAS, DFLT_messageTimeBias);
        this.confirmWaitTime = getInt(pairs, KEY_CONFIRM_WAITTIME, DFLT_confirmWaitTime);
        String s = pairs.getValue(KEY_PROTECTION_SIGALGO);

        if(s == null)
        {
            this.sigAlgos = null;
        }
        else
        {
            Set<String> set = StringUtil.splitAsSet(s, ", ");
            this.sigAlgos = CollectionUtil.unmodifiableSet(set, false, true);
            if(CollectionUtil.isNotEmpty(this.sigAlgos))
            {
                pairs.putUtf8Pair(KEY_PROTECTION_SIGALGO, StringUtil.collectionAsString(this.sigAlgos, ","));
            }
        }

        this.dbEntry = new CmpControlEntry(dbEntry.getName(), pairs.getEncoded());
    }

    public CmpControl(
            final String name,
            final Boolean confirmCert,
            final Boolean sendCaCert,
            final Boolean messageTimeRequired,
            final Boolean sendResponderCert,
            final Integer messageTimeBias,
            final Integer confirmWaitTime,
            final Set<String> sigAlgos)
    {
        ParamChecker.assertNotBlank("name", name);
        CmpUtf8Pairs pairs = new CmpUtf8Pairs();

        this.confirmCert = confirmCert == null ? false: confirmCert;
        pairs.putUtf8Pair(KEY_CONFIRM_CERT, Boolean.toString(this.confirmCert));

        this.sendCaCert = sendCaCert == null ? false : sendCaCert;
        pairs.putUtf8Pair(KEY_SEND_CA, Boolean.toString(this.sendCaCert));

        this.messageTimeRequired = messageTimeRequired == null ? true : messageTimeRequired;
        pairs.putUtf8Pair(KEY_MESSAGETIME_REQUIRED, Boolean.toString(this.messageTimeRequired));

        this.sendResponderCert = sendResponderCert == null ? true : this.sendResponderCert;
        pairs.putUtf8Pair(KEY_SEND_RESPONDER, Boolean.toString(this.sendResponderCert));

        this.messageTimeBias = messageTimeBias == null ? DFLT_messageTimeBias : messageTimeBias;
        pairs.putUtf8Pair(KEY_MESSAGETIME_BIAS, Integer.toString(this.messageTimeBias));

        this.confirmWaitTime = confirmWaitTime == null ? DFLT_confirmWaitTime : confirmWaitTime;
        pairs.putUtf8Pair(KEY_CONFIRM_WAITTIME, Integer.toString(this.confirmWaitTime));

        if(CollectionUtil.isEmpty(sigAlgos))
        {
            this.sigAlgos = null;
        }
        else
        {
            this.sigAlgos = sigAlgos;
            pairs.putUtf8Pair(KEY_PROTECTION_SIGALGO, StringUtil.collectionAsString(this.sigAlgos, ","));
        }

        this.dbEntry = new CmpControlEntry(name, pairs.getEncoded());
    }

    private static boolean getBoolean(
            final CmpUtf8Pairs pairs,
            final String key,
            final boolean defaultValue)
    {
        String s = pairs.getValue(key);
        boolean ret = StringUtil.isBlank(s) ? defaultValue : Boolean.parseBoolean(s);
        pairs.putUtf8Pair(key, Boolean.toString(ret));
        return ret;
    }

    private static int getInt(
            final CmpUtf8Pairs pairs,
            final String key,
            final int defaultValue)
    {
        String s = pairs.getValue(key);
        int ret = StringUtil.isBlank(s) ? defaultValue : Integer.parseInt(s);
        pairs.putUtf8Pair(key, Integer.toString(ret));
        return ret;
    }

    public boolean isConfirmCert()
    {
        return confirmCert;
    }

    public int getMessageTimeBias()
    {
        return messageTimeBias;
    }

    public int getConfirmWaitTime()
    {
        return confirmWaitTime;
    }

    public boolean isSendCaCert()
    {
        return sendCaCert;
    }

    public boolean isSendResponderCert()
    {
        return sendResponderCert;
    }

    public Set<String> getSigAlgos()
    {
        return sigAlgos;
    }

    public boolean isSigAlgoPermitted(
            final AlgorithmIdentifier algId)
    {
        if(sigAlgos == null)
        {
            return true;
        }

        String name;
        try
        {
            name = AlgorithmUtil.getSignatureAlgoName(algId);
        } catch (NoSuchAlgorithmException e)
        {
            return false;
        }

        if(sigAlgos.contains(name))
        {
            return true;
        }

        for(String m : sigAlgos)
        {
            if(AlgorithmUtil.equalsAlgoName(m, name))
            {
                return true;
            }
        }
        return false;
    }

    public CmpControlEntry getDbEntry()
    {
        return dbEntry;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("               name: ").append(dbEntry.getName()).append('\n');
        sb.append("        confirmCert: ").append(confirmCert ? "yes" : "no").append('\n');
        sb.append("         sendCaCert: ").append(sendCaCert ? "yes" : "no").append("\n");
        sb.append("  sendResponderCert: ").append(sendResponderCert ? "yes" : "no").append("\n");
        sb.append("messageTimeRequired: ").append(messageTimeRequired ? "yes" : "no").append("\n");
        sb.append("    messageTimeBias: ").append(messageTimeBias).append(" s").append('\n');
        sb.append("    confirmWaitTime: ").append(confirmWaitTime).append(" s").append('\n');
        sb.append("    signature algos: ").append(StringUtil.collectionAsString(sigAlgos, ",")).append('\n');
        sb.append("               conf: ").append(dbEntry.getConf());

        return sb.toString();
    }

}
