/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */

package net.sourceforge.myvd.protocol.ldap.mina.ldap.message;


/**
 * Search reference protocol response message used to return referrals to the
 * client in response to a search request message.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Revision: 476948 $
 */
public interface SearchResponseReference extends Response
{
    /** Search reference response message type enumeration value */
    MessageTypeEnum TYPE = MessageTypeEnum.SEARCH_RES_REF;


    /**
     * Gets the sequence of LdapUrls as a Referral instance.
     * 
     * @return the sequence of LdapUrls
     */
    Referral getReferral();


    /**
     * Sets the sequence of LdapUrls as a Referral instance.
     * 
     * @param a_referral
     *            the sequence of LdapUrls
     */
    void setReferral( Referral a_referral );
}
