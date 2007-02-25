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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.actions;


import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.IAsn1Container;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.grammar.GrammarAction;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLV;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.Value;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.util.IntegerDecoder;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.util.IntegerDecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessage;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapMessageContainer;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapResponse;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.LdapResult;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * The action used to set the LdapResult result code.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class ResultCodeAction extends GrammarAction
{
    /** The logger */
    private static final Logger log = LoggerFactory.getLogger( ResultCodeAction.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = log.isDebugEnabled();

    public ResultCodeAction()
    {
        super( "Store resultCode" );
    }

    /**
     * The initialization action
     */
    public void action( IAsn1Container container ) throws DecoderException
    {
        LdapMessageContainer ldapMessageContainer = ( LdapMessageContainer ) container;
        LdapMessage message = ldapMessageContainer.getLdapMessage();
        LdapResponse response = message.getLdapResponse();
        LdapResult ldapResult = new LdapResult();
        response.setLdapResult( ldapResult );

        // We don't have to allocate a LdapResult first.

        // The current TLV should be a integer
        // We get it and store it in MessageId
        TLV tlv = ldapMessageContainer.getCurrentTLV();

        Value value = tlv.getValue();
        ResultCodeEnum resultCode = ResultCodeEnum.SUCCESS;

        try
        {
            resultCode = ResultCodeEnum.getResultCode( IntegerDecoder.parse( value, 0, 90 ) );
        }
        catch ( IntegerDecoderException ide )
        {
            log.error( "The result code " + StringTools.dumpBytes( value.getData() ) + " is invalid : "
                + ide.getMessage() + ". The result code must be between (0 .. 90)" );

            throw new DecoderException( ide.getMessage() );
        }

        // Treat the 'normal' cases !
        switch ( resultCode )
        {
            case SUCCESS:
            case OPERATIONS_ERROR:
            case PROTOCOL_ERROR:
            case TIME_LIMIT_EXCEEDED:
            case SIZE_LIMIT_EXCEEDED:
            case COMPARE_FALSE:
            case COMPARE_TRUE:
            case AUTH_METHOD_NOT_SUPPORTED:
            case STRONG_AUTH_REQUIRED:
            case REFERRAL:
            case ADMIN_LIMIT_EXCEEDED:
            case UNAVAILABLE_CRITICAL_EXTENSION:
            case CONFIDENTIALITY_REQUIRED:
            case SASL_BIND_IN_PROGRESS:
            case NO_SUCH_ATTRIBUTE:
            case UNDEFINED_ATTRIBUTE_TYPE:
            case INAPPROPRIATE_MATCHING:
            case CONSTRAINT_VIOLATION:
            case ATTRIBUTE_OR_VALUE_EXISTS:
            case INVALID_ATTRIBUTE_SYNTAX:
            case NO_SUCH_OBJECT:
            case ALIAS_PROBLEM:
            case INVALID_DN_SYNTAX:
            case ALIAS_DEREFERENCING_PROBLEM:
            case INAPPROPRIATE_AUTHENTICATION:
            case INVALID_CREDENTIALS:
            case INSUFFICIENT_ACCESS_RIGHTS:
            case BUSY:
            case UNAVAILABLE:
            case UNWILLING_TO_PERFORM:
            case LOOP_DETECT:
            case NAMING_VIOLATION:
            case OBJECT_CLASS_VIOLATION:
            case NOT_ALLOWED_ON_NON_LEAF:
            case NOT_ALLOWED_ON_RDN:
            case ENTRY_ALREADY_EXISTS:
            case AFFECTS_MULTIPLE_DSAS:
                ldapResult.setResultCode( resultCode );
                break;

            default:
                log.warn( "The resultCode " + resultCode + " is unknown." );
                ldapResult.setResultCode( ResultCodeEnum.OTHER );
        }

        if ( IS_DEBUG )
        {
            log.debug( "The result code is set to " + resultCode );
        }
    }
}
