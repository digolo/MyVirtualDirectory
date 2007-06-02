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


import javax.naming.ConfigurationException;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;


/**
 * A ConfigurationException which associates a resultCode namely the
 * {@link ResultCodeEnum#OTHER} resultCode with the exception.
 * 
 * @see LdapException
 * @see javax.naming.ConfigurationException
 * @see <a
 *      href="http://java.sun.com/j2se/1.4.2/docs/guide/jndi/jndi-ldap-gl.html#EXCEPT">
 *      LDAP ResultCode to JNDI Exception Mappings</a>
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 437007 $
 */
public class LdapConfigurationException extends ConfigurationException implements LdapException
{
    static final long serialVersionUID = 7062168557099947648L;


    /**
     * @see javax.naming.NoPermissionException#NoPermissionException()
     */
    public LdapConfigurationException()
    {
        super();
    }


    /**
     * @see javax.naming.NoPermissionException#NoPermissionException( String )
     */
    public LdapConfigurationException( String explanation )
    {
        super( explanation );
    }


    /**
     * @see javax.naming.NoPermissionException#NoPermissionException( String )
     */
    public LdapConfigurationException( String explanation, Throwable t )
    {
        super( explanation );
        super.setRootCause( t );
    }


    /**
     * Always returns
     * {@link net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum#OTHER}
     * 
     * @see LdapException#getResultCode()
     */
    public ResultCodeEnum getResultCode()
    {
        return ResultCodeEnum.OTHER;
    }
}
