/*
 * Copyright 2008 Marc Boorshtein 
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); 
 * you may not use this file except in compliance with the License. 
 * You may obtain a copy of the License at 
 * 
 * 		http://www.apache.org/licenses/LICENSE-2.0 
 * 
 * Unless required by applicable law or agreed to in writing, software 
 * distributed under the License is distributed on an "AS IS" BASIS, 
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. 
 * See the License for the specific language governing permissions and 
 * limitations under the License.
 */
package net.sourceforge.myvd.server;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.Charset;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.StringTokenizer;
import java.util.UUID;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;

import net.sourceforge.myvd.core.InsertChain;
import net.sourceforge.myvd.core.NameSpace;
import net.sourceforge.myvd.inserts.Insert;
import net.sourceforge.myvd.router.Router;
import net.sourceforge.myvd.server.apacheds.MyVDPartition;
import net.sourceforge.myvd.types.DistinguishedName;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.entry.Attribute;
import org.apache.directory.api.ldap.model.entry.DefaultAttribute;
import org.apache.directory.api.ldap.model.entry.DefaultModification;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.Modification;
import org.apache.directory.api.ldap.model.entry.ModificationOperation;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.filter.PresenceNode;
import org.apache.directory.api.ldap.model.message.AliasDerefMode;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.schema.AttributeType;
import org.apache.directory.api.ldap.model.schema.AttributeTypeOptions;
import org.apache.directory.api.ldap.model.schema.registries.SchemaLoader;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.CsnSyntaxChecker;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.GeneralizedTimeSyntaxChecker;
import org.apache.directory.api.ldap.model.schema.syntaxCheckers.UuidSyntaxChecker;
import org.apache.directory.api.ldap.schemaextractor.SchemaLdifExtractor;
import org.apache.directory.api.ldap.schemaextractor.impl.DefaultSchemaLdifExtractor;
import org.apache.directory.api.ldap.schemaloader.LdifSchemaLoader;
import org.apache.directory.api.ldap.schemamanager.impl.DefaultSchemaManager;
import org.apache.directory.api.util.DateUtils;
import org.apache.directory.api.util.exception.Exceptions;
import org.apache.directory.server.config.ConfigPartitionReader;
import org.apache.directory.server.config.LdifConfigExtractor;
import org.apache.directory.server.config.beans.ConfigBean;
import org.apache.directory.server.config.beans.DirectoryServiceBean;
import org.apache.directory.server.config.builder.ServiceBuilder;
import org.apache.directory.server.core.DefaultDirectoryService;
import org.apache.directory.server.core.api.CacheService;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.InstanceLayout;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.api.schema.SchemaPartition;
import org.apache.directory.server.core.partition.ldif.LdifPartition;
import org.apache.directory.server.core.partition.ldif.SingleFileLdifPartition;
import org.apache.directory.server.ldap.LdapServer;
import org.apache.directory.server.protocol.shared.transport.TcpTransport;
import org.apache.log4j.Logger;
import org.apache.log4j.PropertyConfigurator;
import org.apache.mina.filter.codec.ProtocolCodecFilter;
import org.apache.mina.filter.codec.textline.TextLineCodecFactory;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPException;
import com.novell.ldap.util.DN;

import edu.emory.mathcs.backport.java.util.concurrent.Executors;


public class Server {
	
	static Logger logger;
	

	public final static String VERSION = "0.9.0";
	
	String configFile;
	Properties props;
	private InsertChain globalChain;
	private Router router;

	private ServerCore serverCore;


	private DefaultDirectoryService directoryService;


	private LdapServer ldapServer;


	private boolean isSchemaPartitionFirstExtraction;


	private DefaultSchemaManager schemaManager;


	private LdifPartition schemaLdifPartition;


	private boolean isConfigPartitionFirstExtraction;


	private ConfigPartitionReader cpReader;


	

	private static final Map<String, AttributeTypeOptions> MANDATORY_ENTRY_ATOP_MAP = new HashMap<String, AttributeTypeOptions>();
    private static String[] MANDATORY_ENTRY_ATOP_AT;
    
    /** The configuration partition */
    private SingleFileLdifPartition configPartition;
    
 // variables used during the initial startup to update the mandatory operational
    // attributes
    /** The UUID syntax checker instance */
    private UuidSyntaxChecker uuidChecker = new UuidSyntaxChecker();

    /** The CSN syntax checker instance */
    private CsnSyntaxChecker csnChecker = new CsnSyntaxChecker();

    private GeneralizedTimeSyntaxChecker timeChecker = new GeneralizedTimeSyntaxChecker();
    
	public InsertChain getGlobalChain() {
		return globalChain;
	}

	public Router getRouter() {
		return router;
	}

	public Server(String configFile) throws FileNotFoundException, IOException {
		this.configFile  = configFile;
		
		
		
		this.props = new Properties();
		
		props.load(new FileInputStream(this.configFile));
		
	}
	
	public void startServer() throws Exception {
		String portString;
		
		
		//this is a hack for testing.
		if (logger == null) {
			getDefaultLog();
		}
		
		this.serverCore = new ServerCore(this.props);
		
		this.serverCore.startService();
		
		this.globalChain = serverCore.getGlobalChain();
		this.router = serverCore.getRouter();
		
		/*this.directoryService = new DefaultDirectoryService();
        directoryService.setShutdownHookEnabled(false);
        directoryService.setAccessControlEnabled(false);
        directoryService.setAllowAnonymousAccess(true);
        directoryService.setInstanceLayout(new InstanceLayout(new File("/tmp/test")));
        
        this.initSchemaManager(directoryService.getInstanceLayout());
        this.initSchemaLdifPartition(directoryService.getInstanceLayout());
        
 
        SchemaPartition schemaPartition = new SchemaPartition( schemaManager );
        schemaPartition.setWrappedPartition( schemaLdifPartition );
        directoryService.setSchemaPartition( schemaPartition );
        
        CacheService cacheService = new CacheService();
        cacheService.initialize( directoryService.getInstanceLayout() );
        
        directoryService.setCacheService(cacheService);
        */
		
		this.startApacheDS(new InstanceLayout(new File("/tmp/test")));
        
        
        
        
        
        this.ldapServer = new LdapServer();
        ldapServer.setDirectoryService(directoryService);
		
		portString = props.getProperty("server.listener.port","");
		if (! portString.equals("")) {
			TcpTransport ldapTransport = new TcpTransport(Integer.parseInt(portString));
	        ldapServer.setTransports(ldapTransport);
		}
		
		
        ldapServer.start();
		
		/*portString = props.getProperty("server.secure.listener.port","");
		
		if (! portString.equals("")) {
			String keyStorePath = props.getProperty("server.secure.keystore","");
			logger.debug("Key store : " + keyStorePath);
			
			String keyStorePass = props.getProperty("server.secure.keypass","");
			
			KeyStore keystore;
			try {
				keystore = KeyStore.getInstance("JKS");
				keystore.load(new FileInputStream(keyStorePath), keyStorePass.toCharArray());
				KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
				kmf.init(keystore, keyStorePass.toCharArray());
				SSLContext sslc = SSLContext.getInstance("SSLv3");
				sslc.init(kmf.getKeyManagers(), null, null);
				
				SSLFilter sslFilter = new SSLFilter(sslc);
				DefaultIoFilterChainBuilder chain = new DefaultIoFilterChainBuilder();
		        chain.addLast( "SSL", sslFilter );
		        
		        startLDAP(portString,chain);
			} catch (Throwable t) {
				logger.error("Could not start LDAPS listener",t);
				t.printStackTrace();
			}
		        
		}*/
		
		
		
	}

	private static void getDefaultLog() {
		Properties props = new Properties();
		props.put("log4j.rootLogger", "info,console");
		
		//props.put("log4j.appender.console","org.apache.log4j.RollingFileAppender");
		//props.put("log4j.appender.console.File","/home/mlb/myvd.log");
		props.put("log4j.appender.console","org.apache.log4j.ConsoleAppender");
		props.put("log4j.appender.console.layout","org.apache.log4j.PatternLayout");
		props.put("log4j.appender.console.layout.ConversionPattern","[%d][%t] %-5p %c{1} - %m%n");
		
		
		
		PropertyConfigurator.configure(props);
		logger = Logger.getLogger(Server.class.getName());
	}

	/*private void startLDAP(String portString,IoFilterChainBuilder chainBuilder) throws LdapNamingException, IOException {
		if (! portString.equals("")) {
			logger.debug("Starting server on port : " + portString);
			
			LdapProtocolProvider protocolProvider = new LdapProtocolProvider(this.globalChain,this.router,this.props.getProperty("server.binaryAttribs","userPassword"));
			
//			 Disable the disconnection of the clients on unbind
            SocketAcceptorConfig acceptorCfg = new SocketAcceptorConfig();
            acceptorCfg.setDisconnectOnUnbind( false );
            
            acceptorCfg.setReuseAddress( true );
            
            if (chainBuilder == null) {
            	acceptorCfg.setFilterChainBuilder( new DefaultIoFilterChainBuilder() );
            } else {
            	acceptorCfg.setFilterChainBuilder( chainBuilder );
            }
            acceptorCfg.setThreadModel( threadModel );
            //acceptorCfg.getFilterChain().addLast("codec", new ProtocolCodecFilter( new TextLineCodecFactory( Charset.forName( "UTF-8" ))));
            
            ((SocketSessionConfig)(acceptorCfg.getSessionConfig())).setTcpNoDelay( true );
            
            logger.debug("Port String : " + portString);
            logger.debug("Protocol Prpvider : " + protocolProvider);
            logger.debug("AcceptorConfig : " + acceptorCfg);
            logger.debug("tcpAcceptor : " + tcpAcceptor);
            
            //tcpAcceptor = new SocketAcceptor(((int) Runtime.getRuntime().availableProcessors()) + 1,null);
            tcpAcceptor = new SocketAcceptor();
            
            //try 3 times?
            for (int i=0;i<3;i++) {
            	try {
            		tcpAcceptor.bind( new InetSocketAddress( Integer.parseInt(portString) ), protocolProvider.getHandler(), acceptorCfg );
            		break;
            	} catch (java.net.BindException e) {
            		logger.error("Could not bind to address, waiting 30 seconds to try again",e);
            		try {
						Thread.sleep(30000);
					} catch (InterruptedException e1) {
						
					}
            	}
            }
            
			
			minaRegistry = new SimpleServiceRegistry();
			Service service = new Service( "ldap", TransportType.SOCKET, new InetSocketAddress( Integer.parseInt(portString) ) );
			
			logger.debug("LDAP listener started");
		}
	}*/
	
	public void stopServer() throws Exception {
		//this.minaRegistry.unbindAll();
		logger.info("Shutting down server");
		this.ldapServer.stop();
		this.directoryService.shutdown();
		
		//this.stopLDAP0(Integer.parseInt(props.getProperty("server.listener.port","389")));
		for (int i=0,m=100;i<m;i++) {
			try {
				LDAPConnection con = new LDAPConnection();
				con.connect("127.0.0.1",Integer.parseInt(props.getProperty("server.listener.port","389")));
				try {
					Thread.sleep(100);
				} catch (InterruptedException e) {
					
				}
			} catch (LDAPException e) {
				//logger.error("Error",e);
				break;
			}
		}
		
		this.router.shutDownRouter();
		
		logger.info("Server Stopped");
	}
	
	
	
	public static void main(String[] args) throws Exception {
		
		
		if (System.getProperty("nolog","0").equalsIgnoreCase("0")) {
			String home = args[0];
			home = home.substring(0,home.lastIndexOf(File.separator));
			String loghome = home.substring(0,home.lastIndexOf(File.separator));
			
			Properties props = new Properties();
			
			
			props.load(new FileInputStream(home + "/logging.conf"));
			
			if (! props.containsKey("log4j.rootLogger")) props.put("log4j.rootLogger", "debug,logfile");
			if (! props.containsKey("log4j.appender.logfile")) props.put("log4j.appender.logfile", "org.apache.log4j.RollingFileAppender");
			if (! props.containsKey("log4j.appender.logfile.File")) props.put("log4j.appender.logfile.File",loghome + "/logs/myvd.log");
			if (! props.containsKey("log4j.appender.logfile.MaxFileSize")) props.put("log4j.appender.logfile.MaxFileSize","100KB");
			if (! props.containsKey("log4j.appender.logfile.MaxBackupIndex")) props.put("log4j.appender.logfile.MaxBackupIndex","10");
			if (! props.containsKey("log4j.appender.logfile.layout")) props.put("log4j.appender.logfile.layout","org.apache.log4j.PatternLayout");
			if (! props.containsKey("log4j.appender.logfile.layout.ConversionPattern")) props.put("log4j.appender.logfile.layout.ConversionPattern","[%d][%t] %-5p %c{1} - %m%n");
			
			
			
			
			
			PropertyConfigurator.configure(props);
			
			Server.logger = Logger.getLogger(Server.class.getName());
		} else {
			getDefaultLog();
		}
		logger.info("MyVirtualDirectory Version : " + Server.VERSION);
		logger.info("Starting MyVirtualDirectory server...");
		try {
			Server server = new Server(args[0]);
			server.startServer();
			logger.info("Server started");
		} catch (Throwable t) {
			logger.error("Error starting server : " + t.toString(),t);
		}
        
		
	}

	private Properties getProps() {
		return this.props;
	}
	
	/*private void stopLDAP0( int port )
    {
        try
        {
            // we should unbind the service before we begin sending the notice 
            // of disconnect so new connections are not formed while we process
            List writeFutures = new ArrayList();

            // If the socket has already been unbound as with a successful 
            // GracefulShutdownRequest then this will complain that the service
            // is not bound - this is ok because the GracefulShutdown has already
            // sent notices to to the existing active sessions
            List sessions = null;
            try
            {
                sessions = new ArrayList( tcpAcceptor.getManagedSessions( new InetSocketAddress( port ) ) );
            }
            catch ( IllegalArgumentException e )
            {
                logger.warn( "Seems like the LDAP service (" + port + ") has already been unbound." );
                return;
            }

            tcpAcceptor.unbind( new InetSocketAddress( port ) );
            if ( logger.isInfoEnabled() )
            {
            	logger.info( "Unbind of an LDAP service (" + port + ") is complete." );
            	logger.info( "Sending notice of disconnect to existing clients sessions." );
            }

            // Send Notification of Disconnection messages to all connected clients.
            if ( sessions != null )
            {
                for ( Iterator i = sessions.iterator(); i.hasNext(); )
                {
                    IoSession session = ( IoSession ) i.next();
                    writeFutures.add( session.write( NoticeOfDisconnect.UNAVAILABLE ) );
                }
            }

            // And close the connections when the NoDs are sent.
            Iterator sessionIt = sessions.iterator();
            for ( Iterator i = writeFutures.iterator(); i.hasNext(); )
            {
                WriteFuture future = ( WriteFuture ) i.next();
                future.join( 1000 );
                ( ( IoSession ) sessionIt.next() ).close();
            }
        }
        catch ( Exception e )
        {
        	logger.warn( "Failed to sent NoD.", e );
        }
        
        try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			
		}
        
    }*/
	
	/**
     * Initialize the schema Manager by loading the schema LDIF files
     * 
     * @param instanceLayout the instance layout
     * @throws Exception in case of any problems while extracting and writing the schema files
     */
    private void initSchemaManager( InstanceLayout instanceLayout ) throws Exception
    {
        File schemaPartitionDirectory = new File( instanceLayout.getPartitionsDirectory(), "schema" );

        // Extract the schema on disk (a brand new one) and load the registries
        if ( schemaPartitionDirectory.exists() )
        {
            logger.info( "schema partition already exists, skipping schema extraction" );
        }
        else
        {
            SchemaLdifExtractor extractor = new DefaultSchemaLdifExtractor( instanceLayout.getPartitionsDirectory() );
            extractor.extractOrCopy();
            isSchemaPartitionFirstExtraction = true;
        }

        SchemaLoader loader = new LdifSchemaLoader( schemaPartitionDirectory );
        schemaManager = new DefaultSchemaManager( loader );

        // We have to load the schema now, otherwise we won't be able
        // to initialize the Partitions, as we won't be able to parse
        // and normalize their suffix Dn
        schemaManager.loadAllEnabled();

        List<Throwable> errors = schemaManager.getErrors();

        if ( errors.size() != 0 )
        {
            throw new Exception(Exceptions.printErrors( errors ) ) ;
        }
    }


    /**
     * Initialize the schema partition
     * 
     * @param instanceLayout the instance layout
     * @throws Exception in case of any problems while initializing the SchemaPartition
     */
    private void initSchemaLdifPartition( InstanceLayout instanceLayout ) throws Exception
    {
        File schemaPartitionDirectory = new File( instanceLayout.getPartitionsDirectory(), "schema" );

        // Init the LdifPartition
        schemaLdifPartition = new LdifPartition( schemaManager );
        schemaLdifPartition.setPartitionPath( schemaPartitionDirectory.toURI() );
    }
    
    /**
     * starts various services configured according to the
     * configuration present in the given instance's layout
     *
     * @param instanceLayout the on disk location's layout of the intance to be started
     * @throws Exception
     */
    public void startApacheDS( InstanceLayout instanceLayout ) throws Exception
    {
        File partitionsDir = instanceLayout.getPartitionsDirectory();

        if ( !partitionsDir.exists() )
        {
            logger.info( "partition directory doesn't exist, creating " + partitionsDir.getAbsolutePath() );

            if ( !partitionsDir.mkdirs() )
            {
                throw new IOException( "Could not create directory : '" + partitionsDir + "'" );
            }
        }

        logger.info( "using partition dir " + partitionsDir.getAbsolutePath() );

        CacheService cacheService = new CacheService();
        cacheService.initialize( instanceLayout );

        initSchemaManager( instanceLayout );
        initSchemaLdifPartition( instanceLayout );
        initConfigPartition( instanceLayout, cacheService );

        // Read the configuration
        cpReader = new ConfigPartitionReader( configPartition );

        ConfigBean configBean = cpReader.readConfig();

        DirectoryServiceBean directoryServiceBean = configBean.getDirectoryServiceBean();

        // Initialize the DirectoryService now
        directoryService = (DefaultDirectoryService) initDirectoryService( instanceLayout, directoryServiceBean, cacheService );

        
    }
    
    /**
     * 
     * initializes a LDIF partition for configuration
     * 
     * @param instanceLayout the instance layout
     * @param cacheService the Cache service
     * @throws Exception in case of any issues while extracting the schema
     */
    private void initConfigPartition( InstanceLayout instanceLayout, CacheService cacheService ) throws Exception
    {
        File confFile = new File( instanceLayout.getConfDirectory(), LdifConfigExtractor.LDIF_CONFIG_FILE );

        if ( confFile.exists() )
        {
            logger.info( "config partition already exists, skipping default config extraction" );
        }
        else
        {
            LdifConfigExtractor.extractSingleFileConfig( instanceLayout.getConfDirectory(),
                LdifConfigExtractor.LDIF_CONFIG_FILE, true );
            isConfigPartitionFirstExtraction = true;
        }

        configPartition = new SingleFileLdifPartition( schemaManager );
        configPartition.setId( "config" );
        configPartition.setPartitionPath( confFile.toURI() );
        configPartition.setSuffixDn( new Dn( schemaManager, "ou=config" ) );
        configPartition.setSchemaManager( schemaManager );
        configPartition.setCacheService( cacheService );

        configPartition.initialize();
    }
    
    private DirectoryService initDirectoryService( InstanceLayout instanceLayout,
            DirectoryServiceBean directoryServiceBean, CacheService cacheService ) throws Exception
        {
            logger.info( "Initializing the DirectoryService..." );

            long startTime = System.currentTimeMillis();

            directoryService = (DefaultDirectoryService) ServiceBuilder.createDirectoryService( directoryServiceBean,
                instanceLayout, schemaManager );

            // The schema partition
            SchemaPartition schemaPartition = new SchemaPartition( schemaManager );
            schemaPartition.setWrappedPartition( schemaLdifPartition );
            directoryService.setSchemaPartition( schemaPartition );

            directoryService.addPartition( configPartition );

            // Store the default directories
            directoryService.setInstanceLayout( instanceLayout );

            directoryService.setCacheService( cacheService );

            ArrayList<String> useBase = new ArrayList<String>();
            for (String base : this.serverCore.getNamespaces()) {
            	DN dn = new DN(base);
            	String top = dn.getRDNs().get(dn.getRDNs().size() - 1).toString();
            	if (! useBase.contains(top)) {
            		useBase.add(top);
            	}
            }
            
            for (String top : useBase) {
            	MyVDPartition myvd = new MyVDPartition(this.globalChain,this.router);
            	myvd.setId("myvd-" + top);
            	myvd.setSchemaManager(directoryService.getSchemaManager());
            	myvd.setSuffixDn(new Dn(top));
            	myvd.initialize();
            	
            	directoryService.addPartition(myvd);
            }
            
            
            directoryService.startup();

            AttributeType ocAt = schemaManager.lookupAttributeTypeRegistry( SchemaConstants.OBJECT_CLASS_AT );
            MANDATORY_ENTRY_ATOP_MAP.put( ocAt.getName(), new AttributeTypeOptions( ocAt ) );

            AttributeType uuidAt = schemaManager.lookupAttributeTypeRegistry( SchemaConstants.ENTRY_UUID_AT );
            MANDATORY_ENTRY_ATOP_MAP.put( uuidAt.getName(), new AttributeTypeOptions( uuidAt ) );

            AttributeType csnAt = schemaManager.lookupAttributeTypeRegistry( SchemaConstants.ENTRY_CSN_AT );
            MANDATORY_ENTRY_ATOP_MAP.put( csnAt.getName(), new AttributeTypeOptions( csnAt ) );

            AttributeType creatorAt = schemaManager.lookupAttributeTypeRegistry( SchemaConstants.CREATORS_NAME_AT );
            MANDATORY_ENTRY_ATOP_MAP.put( creatorAt.getName(), new AttributeTypeOptions( creatorAt ) );

            AttributeType createdTimeAt = schemaManager.lookupAttributeTypeRegistry( SchemaConstants.CREATE_TIMESTAMP_AT );
            MANDATORY_ENTRY_ATOP_MAP.put( createdTimeAt.getName(), new AttributeTypeOptions( createdTimeAt ) );

            MANDATORY_ENTRY_ATOP_AT = new String[MANDATORY_ENTRY_ATOP_MAP.size()];

            int pos = 0;

            for ( AttributeTypeOptions attributeTypeOptions : MANDATORY_ENTRY_ATOP_MAP.values() )
            {
                MANDATORY_ENTRY_ATOP_AT[pos++] = attributeTypeOptions.getAttributeType().getName();
            }

            if ( isConfigPartitionFirstExtraction )
            {
                logger.info( "begining to update config partition LDIF files after modifying manadatory attributes" );

                // disable writes to the disk upon every modification to improve performance
                configPartition.setEnableRewriting( false );

                // perform updates
                updateMandatoryOpAttributes( configPartition, directoryService );

                // enable writes to disk, this will save the partition data first if found dirty
                configPartition.setEnableRewriting( true );

                logger.info( "config partition data was successfully updated" );
            }

            if ( isSchemaPartitionFirstExtraction )
            {
                logger.info( "begining to update schema partition LDIF files after modifying manadatory attributes" );

                updateMandatoryOpAttributes( schemaLdifPartition, directoryService );

                logger.info( "schema partition data was successfully updated" );
            }

            logger.info( "DirectoryService initialized in " + ( System.currentTimeMillis() - startTime ) + " milliseconds" );

            return directoryService;
        }
    
    /**
     * 
     * adds mandatory operational attributes {@link #MANDATORY_ENTRY_ATOP_MAP} and updates all the LDIF files.
     * WARN: this method is only called for the first time when schema and config files are bootstrapped
     *       afterwards it is the responsibility of the user to ensure correctness of LDIF files if modified
     *       by hand
     * 
     * Note: we do these modifications explicitly cause we have no idea if each entry's LDIF file has the
     *       correct values for all these mandatory attributes
     * 
     * @param partition instance of the partition Note: should only be those which are loaded before starting the DirectoryService
     * @param dirService the DirectoryService instance
     * @throws Exception
     */
    public void updateMandatoryOpAttributes( Partition partition, DirectoryService dirService ) throws Exception
    {
        CoreSession session = dirService.getAdminSession();

        String adminDn = session.getEffectivePrincipal().getName();

        ExprNode filter = new PresenceNode( SchemaConstants.OBJECT_CLASS_AT );

        EntryFilteringCursor cursor = session.search( partition.getSuffixDn(), SearchScope.SUBTREE, filter,
            AliasDerefMode.NEVER_DEREF_ALIASES, MANDATORY_ENTRY_ATOP_AT );
        cursor.beforeFirst();

        List<Modification> mods = new ArrayList<Modification>();

        while ( cursor.next() )
        {
            Entry entry = cursor.get();

            AttributeType atType = MANDATORY_ENTRY_ATOP_MAP.get( SchemaConstants.ENTRY_UUID_AT ).getAttributeType();

            Attribute uuidAt = entry.get( atType );
            String uuid = ( uuidAt == null ? null : uuidAt.getString() );

            if ( !uuidChecker.isValidSyntax( uuid ) )
            {
                uuidAt = new DefaultAttribute( atType, UUID.randomUUID().toString() );
            }

            Modification uuidMod = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, uuidAt );
            mods.add( uuidMod );

            atType = MANDATORY_ENTRY_ATOP_MAP.get( SchemaConstants.ENTRY_CSN_AT ).getAttributeType();
            Attribute csnAt = entry.get( atType );
            String csn = ( csnAt == null ? null : csnAt.getString() );

            if ( !csnChecker.isValidSyntax( csn ) )
            {
                csnAt = new DefaultAttribute( atType, dirService.getCSN().toString() );
            }

            Modification csnMod = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, csnAt );
            mods.add( csnMod );

            atType = MANDATORY_ENTRY_ATOP_MAP.get( SchemaConstants.CREATORS_NAME_AT ).getAttributeType();
            Attribute creatorAt = entry.get( atType );
            String creator = ( creatorAt == null ? "" : creatorAt.getString().trim() );

            if ( ( creator.length() == 0 ) || ( !Dn.isValid( creator ) ) )
            {
                creatorAt = new DefaultAttribute( atType, adminDn );
            }

            Modification creatorMod = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, creatorAt );
            mods.add( creatorMod );

            atType = MANDATORY_ENTRY_ATOP_MAP.get( SchemaConstants.CREATE_TIMESTAMP_AT ).getAttributeType();
            Attribute createdTimeAt = entry.get( atType );
            String createdTime = ( createdTimeAt == null ? null : createdTimeAt.getString() );

            if ( !timeChecker.isValidSyntax( createdTime ) )
            {
                createdTimeAt = new DefaultAttribute( atType, DateUtils.getGeneralizedTime() );
            }

            Modification createdMod = new DefaultModification( ModificationOperation.REPLACE_ATTRIBUTE, createdTimeAt );
            mods.add( createdMod );

            if ( !mods.isEmpty() )
            {
                logger.debug( "modifying the entry " + entry.getDn() + " after adding missing manadatory operational attributes");
                ModifyOperationContext modifyContext = new ModifyOperationContext( session );
                modifyContext.setEntry( entry );
                modifyContext.setDn( entry.getDn() );
                modifyContext.setModItems( mods );
                partition.modify( modifyContext );
            }

            mods.clear();
        }

        cursor.close();
    }
}
