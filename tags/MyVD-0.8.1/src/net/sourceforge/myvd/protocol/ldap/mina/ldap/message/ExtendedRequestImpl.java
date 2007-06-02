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


import java.util.Arrays;

import javax.naming.NamingException;
import javax.naming.ldap.ExtendedResponse;

import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;


/**
 * ExtendedRequest implementation.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 491848 $
 */
public class ExtendedRequestImpl extends AbstractRequest implements ExtendedRequest
{
    static final long serialVersionUID = 7916990159044177480L;

    /** Extended request's Object Identifier or <b>requestName</b> */
    private String oid;

    /** Extended request's payload or <b>requestValue</b> */
    protected byte[] payload;

    protected ResultResponse response;


    // -----------------------------------------------------------------------
    // Constructors
    // -----------------------------------------------------------------------

    /**
     * Creates a Lockable ExtendedRequest implementing object used to perform
     * extended protocol operation on the server.
     * 
     * @param id
     *            the sequential message identifier
     */
    public ExtendedRequestImpl(final int id)
    {
        super( id, TYPE, true );
    }


    // -----------------------------------------------------------------------
    // ExtendedRequest Interface Method Implementations
    // -----------------------------------------------------------------------

    /**
     * Gets the Object Idendifier corresponding to the extended request type.
     * This is the <b>requestName</b> portion of the ext. req. PDU.
     * 
     * @return the dotted-decimal representation as a String of the OID
     */
    public String getOid()
    {
        return oid;
    }


    /**
     * Sets the Object Idendifier corresponding to the extended request type.
     * 
     * @param oid
     *            the dotted-decimal representation as a String of the OID
     */
    public void setOid( String oid )
    {
        this.oid = oid;
    }


    /**
     * Gets the extended request's <b>requestValue</b> portion of the PDU. The
     * form of the data is request specific and is determined by the extended
     * request OID.
     * 
     * @return byte array of data
     */
    public byte[] getPayload()
    {
        return payload;
    }


    /**
     * Sets the extended request's <b>requestValue</b> portion of the PDU.
     * 
     * @param payload
     *            byte array of data encapsulating ext. req. parameters
     */
    public void setPayload( byte[] payload )
    {
        this.payload = payload;
    }


    // ------------------------------------------------------------------------
    // SingleReplyRequest Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Gets the protocol response message type for this request which produces
     * at least one response.
     * 
     * @return the message type of the response.
     */
    public MessageTypeEnum getResponseType()
    {
        return RESP_TYPE;
    }


    /**
     * The result containing response for this request.
     * 
     * @return the result containing response for this request
     */
    public ResultResponse getResultResponse()
    {
        if ( response == null )
        {
            response = new ExtendedResponseImpl( getMessageId() );
        }

        return response;
    }


    /**
     * Checks to see if an object equals this ExtendedRequest.
     * 
     * @param obj
     *            the object to be checked for equality
     * @return true if the obj equals this ExtendedRequest, false otherwise
     */
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }

        if ( !super.equals( obj ) )
        {
            return false;
        }

        ExtendedRequest req = ( ExtendedRequest ) obj;
        if ( oid != null && req.getOid() == null )
        {
            return false;
        }

        if ( oid == null && req.getOid() != null )
        {
            return false;
        }

        if ( oid != null && req.getOid() != null )
        {
            if ( !oid.equals( req.getOid() ) )
            {
                return false;
            }
        }

        if ( payload != null && req.getPayload() == null )
        {
            return false;
        }

        if ( payload == null && req.getPayload() != null )
        {
            return false;
        }

        if ( payload != null && req.getPayload() != null )
        {
            if ( !Arrays.equals( payload, req.getPayload() ) )
            {
                return false;
            }
        }

        return true;
    }


    /**
     * Get a String representation of an Extended Request
     * 
     * @return an Extended Request String
     */
    public String toString()
    {
        StringBuffer sb = new StringBuffer();

        sb.append( "    Extended request\n" );
        sb.append( "        Request name : '" ).append( oid ).append( "'\n" );

        if ( oid != null )
        {
            sb.append( "        Request value : '" ).append( StringTools.utf8ToString( payload ) ).append( '/' )
                .append( StringTools.dumpBytes( payload ) ).append( "'\n" );
        }

        return sb.toString();
    }


    public String getID()
    {
        return getOid();
    }


    public byte[] getEncodedValue()
    {
        return getPayload();
    }


    public ExtendedResponse createExtendedResponse( String id, byte[] berValue, int offset, int length )
        throws NamingException
    {
        return null;
    }
}
