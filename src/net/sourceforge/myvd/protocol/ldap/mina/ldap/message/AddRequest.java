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


import javax.naming.directory.Attributes;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.name.LdapDN;

import com.novell.ldap.LDAPAttributeSet;


/**
 * Add protocol operation request used to add a new entry to the DIT.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Revision: 476948 $
 */
public interface AddRequest extends SingleReplyRequest, AbandonableRequest
{
    /** LDAPv3 add request type enum code */
    MessageTypeEnum TYPE = MessageTypeEnum.ADD_REQUEST;

    /** LDAPv3 add response type enum code */
    MessageTypeEnum RESP_TYPE = AddResponse.TYPE;


    /**
     * Gets the distinguished name of the entry to add.
     * 
     * @return the Dn of the added entry.
     */
    LdapDN getEntry();


    /**
     * Sets the distinguished name of the entry to add.
     * 
     * @param entry
     *            the Dn of the added entry.
     */
    void setEntry( LdapDN entry );


    /**
     * Gets the attributes of the entry to add.
     * 
     * @return the Attributes containing attribute value pairs.
     */
    Attributes getAttributes();


    /**
     * Sets the attribute value pairs of the entry to add.
     * 
     * @param attributes
     *            the Attributes with attribute value pairs for the added entry.
     */
    void setAttributes( Attributes attributes );


	public LDAPAttributeSet getAttribSet();
}
