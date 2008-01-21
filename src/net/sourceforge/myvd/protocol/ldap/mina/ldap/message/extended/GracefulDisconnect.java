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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.message.extended;


import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.List;

import javax.naming.NamingException;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.Asn1Decoder;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.EncoderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.GracefulDisconnectContainer;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.GracefulDisconnectDecoder;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.util.LdapURL;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.util.LdapURLEncodingException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ExtendedResponseImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.Referral;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ReferralImpl;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.ResultCodeEnum;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An unsolicited notification, extended response, intended for notifying
 * clients of upcoming disconnection due to intended service windows. Unlike the
 * {@link NoticeOfDisconnect} this response contains additional information about
 * the amount of time the server will be offline and exactly when it intends to
 * shutdown.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev: 482314 $
 */
public class GracefulDisconnect extends ExtendedResponseImpl
{
    private static final long serialVersionUID = -4682291068700593492L;

    public static final String EXTENSION_OID = "1.3.6.1.4.1.18060.0.1.5";

    private static final Logger log = LoggerFactory.getLogger( GracefulDisconnect.class );

    /** offline Time after disconnection */
    private int timeOffline;

    /** Delay before disconnection */
    private int delay;

    /** String based LDAP URL that may be followed for replicated namingContexts */
    private Referral replicatedContexts = new ReferralImpl();


    public GracefulDisconnect(byte[] value) throws NamingException
    {
        super( 0, EXTENSION_OID );
        this.value = value;
        decodeValue();
    }


    public GracefulDisconnect(int timeOffline, int delay)
    {
        super( 0, EXTENSION_OID );
        super.oid = EXTENSION_OID;
        this.timeOffline = timeOffline;
        this.delay = delay;

        StringBuffer buf = new StringBuffer();
        buf.append( "The server will disconnect and will be unavailable for " ).append( timeOffline );
        buf.append( " minutes in " ).append( delay ).append( " seconds." );

        super.getLdapResult().setErrorMessage( buf.toString() );
        super.getLdapResult().setMatchedDn( null );
        super.getLdapResult().setResultCode( ResultCodeEnum.UNAVAILABLE );

        encodeResponse();
    }


    private void decodeValue() throws NamingException
    {
        GracefulDisconnectDecoder decoder = new GracefulDisconnectDecoder();
        net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.GracefulDisconnect codec = null;
        try
        {
            codec = ( net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.GracefulDisconnect ) decoder
                .decode( value );
            this.timeOffline = codec.getTimeOffline();
            this.delay = codec.getDelay();
            super.getLdapResult().setResultCode( ResultCodeEnum.SUCCESS );
            List contexts = codec.getReplicatedContexts();
            for ( int ii = 0; ii < contexts.size(); ii++ )
            {
                replicatedContexts.addLdapUrl( contexts.get( ii ).toString() );
            }
        }
        catch ( DecoderException e )
        {
            log.error( "Failed to decode response value", e );
            throw new RuntimeException( e );
        }
    }


    private void encodeResponse()
    {
        net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.GracefulDisconnect codec = new net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.GracefulDisconnect();
        codec.setTimeOffline( this.timeOffline );
        codec.setDelay( this.delay );
        Iterator contexts = this.replicatedContexts.getLdapUrls().iterator();
        while ( contexts.hasNext() )
        {
            String urlstr = ( String ) contexts.next();
            LdapURL url = null;
            try
            {
                url = new LdapURL( urlstr );
            }
            catch ( LdapURLEncodingException e )
            {
                log.error( "Failed while parsing LDAP url " + urlstr, e );
                continue;
            }
            codec.addReplicatedContexts( url );
        }

        try
        {
            super.value = codec.encode( null ).array();
        }
        catch ( EncoderException e )
        {
            log.error( "Failed to encode message value.", e );
            throw new RuntimeException( e );
        }
    }


    // ------------------------------------------------------------------------
    // ExtendedResponse Interface Method Implementations
    // ------------------------------------------------------------------------

    /**
     * Gets the reponse OID specific encoded response values.
     * 
     * @return the response specific encoded response values.
     */
    public byte[] getResponse()
    {
        if ( value == null )
        {
            encodeResponse();
        }
        return value;
    }


    /**
     * Sets the reponse OID specific encoded response values.
     * 
     * @param value
     *            the response specific encoded response values.
     */
    public void setResponse( byte[] value )
    {
        ByteBuffer bb = ByteBuffer.wrap( value );
        GracefulDisconnectContainer container = new GracefulDisconnectContainer();
        Asn1Decoder decoder = new Asn1Decoder();
        try
        {
            decoder.decode( bb, container );
        }
        catch ( DecoderException e )
        {
            log.error( "Failed while decoding response", e );
        }
        catch ( NamingException e )
        {
            log.error( "Failed while decoding response", e );
        }

        net.sourceforge.myvd.protocol.ldap.mina.ldap.codec.extended.operations.GracefulDisconnect codec = container
            .getGracefulDisconnect();
        this.delay = codec.getDelay();
        this.timeOffline = codec.getTimeOffline();
        List contexts = codec.getReplicatedContexts();
        for ( int ii = 0; ii < contexts.size(); ii++ )
        {
            LdapURL url = ( LdapURL ) contexts.get( ii );
            replicatedContexts.addLdapUrl( url.toString() );
        }

        this.value = value;
    }


    /**
     * Gets the OID uniquely identifying this extended response (a.k.a. its
     * name).
     * 
     * @return the OID of the extended response type.
     */
    public String getResponseName()
    {
        return EXTENSION_OID;
    }


    /**
     * Sets the OID uniquely identifying this extended response (a.k.a. its
     * name).
     * 
     * @param oid
     *            the OID of the extended response type.
     */
    public void setResponseName( String oid )
    {
        throw new UnsupportedOperationException( "the OID is fixed: " + EXTENSION_OID );
    }


    // -----------------------------------------------------------------------
    // Parameters of the Extended Response Value
    // -----------------------------------------------------------------------

    public void setDelay( int delay )
    {
        this.delay = delay;
    }


    public void setTimeOffline( int timeOffline )
    {
        this.timeOffline = timeOffline;
    }


    public int getDelay()
    {
        return delay;
    }


    public int getTimeOffline()
    {
        return timeOffline;
    }


    public Referral getReplicatedContexts()
    {
        return replicatedContexts;
    }
}
