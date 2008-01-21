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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.exception;


import javax.naming.directory.AttributeInUseException;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;


/**
 * A subclass of AttributeInUseException which holds the LDAP resultCode
 * associated with the exception.
 * 
 * @see <a
 *      href="http://java.sun.com/j2se/1.4.2/docs/guide/jndi/jndi-ldap-gl.html#EXCEPT">
 *      LDAP ResultCode to JNDI Exception Mappings</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 477298 $
 */
public class LdapAttributeInUseException extends AttributeInUseException implements LdapException
{
    static final long serialVersionUID = 886120483680893537L;


    /**
     * @see AttributeInUseException#AttributeInUseException()
     */
    public LdapAttributeInUseException()
    {
        super();
    }


    /**
     * @see AttributeInUseException#AttributeInUseException(String)
     */
    public LdapAttributeInUseException(String explanation)
    {
        super( explanation );
    }


    /**
     * @see LdapException#getResultCode()
     */
    public ResultCodeEnum getResultCode()
    {
        return ResultCodeEnum.ATTRIBUTE_OR_VALUE_EXISTS;
    }
}
