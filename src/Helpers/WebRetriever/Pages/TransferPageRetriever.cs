using System;
using System.Collections.Generic;
using System.Linq;
using FantasyPremierLeagueApi.Helpers.Logger;
using System.Net;
using Newtonsoft.Json.Linq;

namespace FantasyPremierLeagueApi.Helpers.WebRetriever.Pages
{
    public class TransferPageRetriever
    {
        private const   string  _TRANSFERS_PAGE   = "https://fantasy.premierleague.com/drf/transfers";
        private         ILogger _logger;
        private         JObject _jsonData;

        public TransferPageRetriever(ILogger logger, CookieContainer cookies)
        {
            _logger = logger;

            var requester = new WebPageRequester(_logger);;
            var json = requester.Get(_TRANSFERS_PAGE, ref cookies);
            _jsonData = JObject.Parse(json);
        }

        /// <returns>Dictionary mapping player id to transfer value in 100,000's</returns>
        public Dictionary<int,int> GetMyTeamTransferValues()
        {
            var result = new Dictionary<int, int>();

            var picks = _jsonData?.Property("picks")?.Value?.ToObject<JArray>();
            if (picks != null)
            {
                foreach (var pick in picks.OfType<JObject>())
                {
                    var playerId = pick?.Property("element")?.Value?.ToObject<int>() ?? 0;
                    var salePrice = pick?.Property("selling_price")?.Value?.ToObject<decimal>() ?? 0;
                    if (playerId <= 0)
                        continue;
                    //salePrice /= 10;
                    result[playerId] = (int)salePrice;
                }
            }
            return result;
        }

        /// <returns>The amount the logged on user has in the bank</returns>
        public decimal GetRemainingBudget()
        {
            var remaining = _jsonData?.Property("helper")?.Value?.ToObject<JObject>()
                                     ?.Property("bank")?.Value?.ToObject<decimal>() ?? 0;
            remaining /= 10;
            return remaining;
        }
    }
}
