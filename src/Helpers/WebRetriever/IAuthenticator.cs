using System.Net;

namespace FantasyPremierLeagueApi.Helpers.WebRetriever
{
    public interface IAuthenticator
    {
        CookieContainer Authenticate(string username, string password);
    }
}
