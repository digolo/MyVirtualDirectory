package net.sourceforge.myvd.higgins.idas.contextProvider.test;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.Provider;
import java.security.Security;

import org.eclipse.higgins.idas.AuthNNamePasswordMaterials;
import org.eclipse.higgins.idas.IAttribute;
import org.eclipse.higgins.idas.IContext;
import org.eclipse.higgins.idas.IContextFactory;
import org.eclipse.higgins.idas.IDigitalSubject;
import org.eclipse.higgins.idas.IPropertyValue;
import org.eclipse.higgins.idas.IdASException;
import org.eclipse.higgins.idas.IdASRegistry;

import net.sourceforge.myvd.higgins.idas.contextProvider.MyVDContextFactory;
import net.sourceforge.myvd.test.util.StartOpenLDAP;
import junit.framework.TestCase;

public class TestMyVDCPFactory extends TestCase {

	private static String _cardID = "file://" + System.getenv("PROJ_DIR") + "/test/test-config.xml";
	private static String _username = "mikemci";
	private static String _password = "secret";
	private static String[] _claims = {"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname",
												"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
												"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"};
	
	private StartOpenLDAP testServer;

	protected void setUp() throws Exception {
		this.testServer = new StartOpenLDAP();
		System.setProperty("nolog","1");
		this.testServer.startServer(System.getenv("PROJ_DIR") + "/test/novel-openldap",50389,"cn=admin,o=bandit","manager");
	}

	protected void tearDown() throws Exception {
		this.testServer.stopServer();
	}
	
	public void testContextFactory() throws Exception {
		IContext context = null;
		IdASRegistry registry = new IdASRegistry();
		Iterable<IContextFactory> factories;
		URI contextRef;

		registry.registerContextFactory(new MyVDContextFactory());
		
		Provider p[] = Security.getProviders();
		for (Provider pv : p)
			System.out.println(pv.toString());

	
			contextRef = new URI(_cardID);
			// Find the factory for our contextRef
			factories = registry.getContextFactories( contextRef);		
			
			for( IContextFactory factory : factories) 
			{
				System.out.println("Factory : " + factory);
				try 
				{
					context = factory.createContext( contextRef);
					break;
				}
				catch( IdASException e) 
				{
					e.printStackTrace();
					continue;
				}
			}
			
			if( context == null) 
			{
				throw new IdASException( "Failed to create context");
			}
			
			context.open(new AuthNNamePasswordMaterials(_username, _password));
			// NOTE: The subject is now authenticated
			
			// Get the requested subject and display the requested claims
			IDigitalSubject subject = context.getSubject(_username);
			System.out.println("Subject cuid: " + subject.getUniqueID());
			System.out.println("Subject type: " + subject.getType());
			for (String claim : _claims) 
			{
				IAttribute attr = subject.getAttribute(new URI(claim));
				if (attr == null)
				{
					System.out.println(claim + " not populated on subject");
					continue;
				}
				System.out.println(attr.getType());
				Iterable<IPropertyValue> propValues = attr.getValues();
				for (IPropertyValue propVal : propValues)
				{
					Object val = propVal.getData();
					if (val instanceof String)
						System.out.println(val);
					else
						System.out.println("Unknown: " + val.toString());
				}
			}
			
		
	}

}
