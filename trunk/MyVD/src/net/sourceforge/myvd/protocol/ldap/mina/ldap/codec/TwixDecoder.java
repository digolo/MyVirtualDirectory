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
package net.sourceforge.myvd.protocol.ldap.mina.ldap.codec;


import java.io.InputStream;
import java.nio.ByteBuffer;
import java.util.Set;

import javax.naming.NamingException;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.Asn1Decoder;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.ber.tlv.TLVStateEnum;

import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.DecoderException;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.stateful.DecoderCallback;
import net.sourceforge.myvd.protocol.ldap.mina.asn1.codec.stateful.DecoderMonitor;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.spi.Provider;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.spi.ProviderDecoder;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.message.spi.ProviderException;
import net.sourceforge.myvd.protocol.ldap.mina.ldap.util.StringTools;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The TwixDecoder decodes ASN.1 BER encoded PDUs.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 */
public class TwixDecoder implements ProviderDecoder
{
    /** The logger */
    private static Logger log = LoggerFactory.getLogger( TwixDecoder.class );

    /** A speedup for logger */
    private static final boolean IS_DEBUG = log.isDebugEnabled();

    /** The associated Provider */
    private final Provider provider;

    /** The message container for this instance */
    private final LdapMessageContainer ldapMessageContainer;

    /** The Ldap BDER decoder instance */
    private final Asn1Decoder ldapDecoder;

    /** The callback to call when the decoding is done */
    private DecoderCallback decoderCallback;


    /**
     * Creates an instance of a Twix Decoder implementation.
     * 
     * @param provider the owning provider.
     * @param binaries The binary attributes set
     */
    public TwixDecoder(Provider provider, Set binaries)
    {
        this.provider = provider;
        ldapMessageContainer = new LdapMessageContainer( binaries );
        ldapDecoder = new LdapDecoder();
    }


    /**
     * Decodes a PDU
     * 
     * @param encoded The PDU containing the LdapMessage to decode
     * @throws DecoderExceptionIf anything went wrong
     */
    public void decode( Object encoded ) throws DecoderException
    {
        ByteBuffer buf;
        int position = 0;

        if ( encoded instanceof ByteBuffer )
        {
            buf = ( ByteBuffer ) encoded;
        }
        else if ( encoded instanceof byte[] )
        {
            buf = ByteBuffer.wrap( ( byte[] ) encoded );
        }
        else
        {
            throw new DecoderException( "Expected either a byte[] or " + "ByteBuffer argument but got a "
                + encoded.getClass() );
        }

        while ( buf.hasRemaining() )
        {
            try
            {
                ldapDecoder.decode( buf, ldapMessageContainer );
    
                if ( IS_DEBUG )
                {
                    log.debug( "Decoding the PDU : " );
    
                    int size = buf.position();
                    buf.flip();
                    
                	byte[] array = new byte[ size - position ];
                	
                	for ( int i = position; i < size; i++ )
                	{
                		array[ i ] = buf.get();
                	}
    
                    position = size;
                    
                    log.debug( StringTools.dumpBytes( array ) );
                }
                
                if ( ldapMessageContainer.getState() == TLVStateEnum.PDU_DECODED )
                {
                    if ( IS_DEBUG )
                    {
                        log.debug( "Decoded LdapMessage : " + ldapMessageContainer.getLdapMessage() );
                        buf.mark();
                    }
    
                    decoderCallback.decodeOccurred( null, ldapMessageContainer.getLdapMessage() );
                    ldapMessageContainer.clean();
                }
                else
                {
                	if ( IS_DEBUG )
                	{
                		
                	}
                }
            }
            catch ( NamingException lne )
            {
                
            }
        }
    }


    /**
     * Feeds the bytes within the input stream to the digester to generate the
     * resultant decoded Message.
     * 
     * @param in The InputStream containing the PDU to be decoded
     * @throws ProviderException If the decoding went wrong
     */
    private void digest( InputStream in ) throws ProviderException
    {
        byte[] buf;

        try
        {
            int amount;

            while ( in.available() > 0 )
            {
                buf = new byte[in.available()];

                if ( ( amount = in.read( buf ) ) == -1 )
                {
                    break;
                }

                ldapDecoder.decode( ByteBuffer.wrap( buf, 0, amount ), ldapMessageContainer );
            }
        }
        catch ( Exception e )
        {
            log.error( "Twix decoder failure : " + e.getMessage() );
            ProviderException pe = new ProviderException( provider, "Twix decoder failure!" );
            pe.addThrowable( e );
            throw pe;
        }
    }


    /**
     * Decodes a PDU from an input stream into a Snickers compiler generated
     * stub envelope.
     * 
     * @param lock Lock object used to exclusively read from the input stream
     * @param in The input stream to read and decode PDU bytes from
     * @return return decoded stub
     */
    public Object decode( Object lock, InputStream in ) throws ProviderException
    {
        if ( lock == null )
        {
            digest( in );

            if ( ldapMessageContainer.getState() == TLVStateEnum.PDU_DECODED )
            {
                if ( IS_DEBUG )
                {
                    log.debug( "Decoded LdapMessage : " + ldapMessageContainer.getLdapMessage() );
                }

                return ldapMessageContainer.getLdapMessage();
            }
            else
            {
                log.error( "Twix decoder failure, PDU does not contain enough data" );
                ProviderException pe = new ProviderException( provider, "Twix decoder failure!" );
                pe.addThrowable( new DecoderException( "The input stream does not contain a full PDU" ) );
                throw pe;
            }
        }
        else
        {
            try
            {
                // Synchronize on the input lock object to prevent concurrent
                // reads
                synchronized ( lock )
                {
                    digest( in );

                    // Notify/awaken threads waiting to read from input stream
                    lock.notifyAll();
                }
            }
            catch ( Exception e )
            {
                log.error( "Twix decoder failure : " + e.getMessage() );
                ProviderException pe = new ProviderException( provider, "Twix decoder failure!" );
                pe.addThrowable( e );
                throw pe;
            }

            if ( ldapMessageContainer.getState() == TLVStateEnum.PDU_DECODED )
            {
                if ( IS_DEBUG )
                {
                    log.debug( "Decoded LdapMessage : " + ldapMessageContainer.getLdapMessage() );
                }

                return ldapMessageContainer.getLdapMessage();
            }
            else
            {
                log.error( "Twix decoder failure : The input stream does not contain a full PDU" );
                ProviderException pe = new ProviderException( provider, "Twix decoder failure!" );
                pe.addThrowable( new DecoderException( "The input stream does not contain a full PDU" ) );
                throw pe;
            }
        }
    }


    /**
     * Gets the Provider that this Decoder implementation is part of.
     * 
     * @return the owning provider.
     */
    public Provider getProvider()
    {
        return provider;
    }


    /**
     * Not used ...
     * 
     * @deprecated
     */
    public void setDecoderMonitor( DecoderMonitor monitor )
    {
    }


    /**
     * Set the callback to call when the PDU has been decoded
     * 
     * @param cb The callback
     */
    public void setCallback( DecoderCallback cb )
    {
        decoderCallback = cb;
    }
}
