package net.sourceforge.myvd.higgins.idas.contextProvider;

public class BasicUsernamePasswordIdentity
{
	private String _username;
	private String _password;
	
	public BasicUsernamePasswordIdentity(String username, String password)
	{
		_username = username;
		_password = password;
	}
	
	public String getUsername() {
		return _username;
	}
	
	public String getPassword() {
		return _password;
	}

}
