/*
 *
 * This file is part of the XiPKI project.
 * Copyright (c) 2013-2016 Lijun Liao
 * Author: Lijun Liao
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License
 * (version 3 or later at your option)
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

package org.xipki.ca.common;

import java.io.Serializable;

/**
 * @author Lijun Liao
 */

public class CmpControl implements Serializable
{
    private static final long serialVersionUID = 1L;
    private static final int DFLT_messageTimeBias = 300; // 300 seconds
    private static final int DFLT_confirmWaitTime = 300; // 300 seconds

    public static final String name = "default";
    private boolean requireConfirmCert;
    private boolean sendCaCert;

    private boolean messageTimeRequired = true;
    private boolean sendResponderCert = true;

    public boolean isMessageTimeRequired()
    {
        return messageTimeRequired;
    }

    public void setMessageTimeRequired(boolean messageTimeRequired)
    {
        this.messageTimeRequired = messageTimeRequired;
    }

    private int messageTimeBias = DFLT_messageTimeBias;
    private int confirmWaitTime = DFLT_confirmWaitTime;

    private static final CmpControl defaultInstance;
    static
    {
        defaultInstance = new CmpControl();
        defaultInstance.setRequireConfirmCert(false);
    }

    public static CmpControl getDefaultCmpControlEntry()
    {
        return defaultInstance;
    }

    public CmpControl()
    {
    }

    public boolean isRequireConfirmCert()
    {
        return requireConfirmCert;
    }

    public void setRequireConfirmCert(boolean requireConfirmCert)
    {
        this.requireConfirmCert = requireConfirmCert;
    }

    public int getMessageTimeBias()
    {
        return messageTimeBias;
    }

    public void setMessageBias(int messageTimeBias)
    {
        this.messageTimeBias = messageTimeBias;
    }

    public int getConfirmWaitTime()
    {
        return confirmWaitTime;
    }

    public void setConfirmWaitTime(int confirmWaitTime)
    {
        this.confirmWaitTime = confirmWaitTime;
    }

    public boolean isSendCaCert()
    {
        return sendCaCert;
    }

    public void setSendCaCert(boolean sendCaCert)
    {
        this.sendCaCert = sendCaCert;
    }

    @Override
    public String toString()
    {
        StringBuilder sb = new StringBuilder();
        sb.append("name: ").append(name).append('\n');
        sb.append("requireConfirmCert: ").append(requireConfirmCert ? "yes" : "no").append('\n');
        sb.append("sendCaCert: ").append(sendCaCert ? "yes" : "no").append("\n");
        sb.append("sendResponderCert: ").append(sendResponderCert ? "yes" : "no").append("\n");
        sb.append("messageTimeRequired: ").append(messageTimeRequired ? "yes" : "no").append("\n");
        sb.append("messageTimeBias: ").append(messageTimeBias).append(" s").append('\n');
        sb.append("confirmWaitTime: ").append(confirmWaitTime).append(" s");

        return sb.toString();
    }

    public boolean isSendResponderCert()
    {
        return sendResponderCert;
    }

    public void setSendResponderCert(boolean sendResponderCert)
    {
        this.sendResponderCert = sendResponderCert;
    }

}
