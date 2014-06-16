/*
 * Copyright (c) 2014 xipki.org
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License
 *
 */

package org.xipki.ca.cmp.server;

public class CmpControl
{
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
