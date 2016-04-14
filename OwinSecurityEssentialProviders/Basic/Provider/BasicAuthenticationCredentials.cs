namespace OwinSecurityEssentialProviders.Basic
{
    public class BasicAuthenticationCredentials
    {
        public string Username { get; set; }

        public string Password { get; set; }


        public BasicAuthenticationCredentials() { }

        public BasicAuthenticationCredentials(string username, string password)
        {
            Username = username;
            Password = password;
        }
    }
}
