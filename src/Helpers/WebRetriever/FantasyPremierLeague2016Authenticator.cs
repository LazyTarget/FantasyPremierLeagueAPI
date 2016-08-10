#region license
// Copyright (c) 2015 Mark Hammond
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Net;
using System.Diagnostics;
using FantasyPremierLeagueApi.Helpers.Logger;
using HtmlAgilityPack;

namespace FantasyPremierLeagueApi.Helpers.WebRetriever
{
    public class FantasyPremierLeague2016Authenticator
    {
        private static string _URL_LOGIN                 = "https://fantasy.premierleague.com/accounts/login/";
        private static string _URL_LOGIN_CONFIRM         = "https://fantasy.premierleague.com/a/login?a={0}&state=success&r={1}&e=3600&s=read+write";
        private static string _FIELD_USERNAME            = "login";
        private static string _FIELD_PASSWORD            = "password";

        private ILogger      _logger;

        public FantasyPremierLeague2016Authenticator(ILogger logger)
        {
            _logger = logger;
        }


        public CookieContainer Authenticate(string username, string password)
        {
            try
            {
                System.Net.ServicePointManager.Expect100Continue = false;

                System.Net.HttpWebResponse resp;
                var requester = new WebPageRequester(_logger);
                var cookies = new CookieContainer();
                
                _logger.WriteDebugMessage("GET Login");
                //var html = requester.Get(_URL_LOGIN, ref cookies, out resp);
                var url = "https://users.premierleague.com/accounts/login/";
                var html = requester.MakeRequest(
                    url: url, 
                    contenttype: null, 
                    method: "GET",
                    data: null,
                    refCookies: ref cookies, 
                    resp: out resp,
                    referer: null
                );
                DumpCookies(cookies);

                

                var uri = new Uri("https://users.premierleague.com/");
                var c = cookies.GetCookies(uri);
                var csrfmiddlewaretoken = c["csrftoken"]?.Value;

                if (string.IsNullOrWhiteSpace(csrfmiddlewaretoken))
                {
                    var htmlDoc = new HtmlDocument();
                    htmlDoc.LoadHtml(html);
                    var loginForm = htmlDoc.DocumentNode.SelectSingleNode("//form[@class='ism-form__login-box']");
                    var csrfHiddenInput = loginForm?.SelectSingleNode("//input[@name='csrfmiddlewaretoken']");
                    csrfmiddlewaretoken = csrfHiddenInput?.GetAttributeValue("value", null);
                }
                
                var parameters = "";
                parameters += string.Format("{0}={1}&", "csrfmiddlewaretoken", csrfmiddlewaretoken);
                parameters += string.Format("{0}={1}&", _FIELD_USERNAME, Uri.EscapeDataString(username));
                parameters += string.Format("{0}={1}&", _FIELD_PASSWORD, Uri.EscapeDataString(password));
                parameters += string.Format("{0}={1}&", "app", "plusers");
                parameters += string.Format("{0}={1}&", "redirect_uri", "https://users.premierleague.com/");
                parameters = parameters.Trim('&');
                //var response = requester.Post(_URL_LOGIN, parameters, ref cookies, out resp);
                url = "https://users.premierleague.com/accounts/login/";
                _logger.WriteDebugMessage("POST Login");
                var response = requester.MakeRequest(
                    url: url,
                    contenttype: "application/x-www-form-urlencoded",
                    method: "POST",
                    data: parameters,
                    refCookies: ref cookies,
                    resp: out resp,
                    referer: "https://users.premierleague.com/"
                );
                DumpCookies(cookies);


                _logger.WriteDebugMessage("Begin copy of cookies");
                // copy cookies between sub-domains
                var uriSource = new Uri("https://users.premierleague.com/");
                var uriTarget = new Uri("https://fantasy.premierleague.com/");
                var sourceCookies = cookies.GetCookies(uriSource);
                cookies.SetCookies(uriTarget, sourceCookies["sessionid"].ToString());
                cookies.SetCookies(uriTarget, sourceCookies["pl_profile"].ToString());
                if (string.IsNullOrWhiteSpace(cookies.GetCookies(uriTarget)["csrftoken"]?.Value))
                {
                    cookies.SetCookies(uriTarget, sourceCookies["csrftoken"].ToString());
                }

                uriTarget = new Uri("https://premierleague.com/");
                sourceCookies = cookies.GetCookies(uriSource);
                cookies.SetCookies(uriTarget, sourceCookies["sessionid"].ToString());
                cookies.SetCookies(uriTarget, sourceCookies["pl_profile"].ToString());
                if (string.IsNullOrWhiteSpace(cookies.GetCookies(uriTarget)["csrftoken"]?.Value))
                {
                    cookies.SetCookies(uriTarget, sourceCookies["csrftoken"].ToString());
                }
                _logger.WriteDebugMessage("Cookies have been copied");
                DumpCookies(cookies);



                _logger.WriteDebugMessage("GET a/team/my");
                url = "https://fantasy.premierleague.com/a/team/my";
                var response2 = requester.Get(url, ref cookies, out resp);
                DumpCookies(cookies);

                _logger.WriteDebugMessage("GET drf/bootstrap-dynamic");
                url = "https://fantasy.premierleague.com/drf/bootstrap-dynamic";
                var response3 = requester.Get(url, ref cookies, out resp);
                DumpCookies(cookies);

                _logger.WriteDebugMessage("GET drf/transfers");
                url = "https://fantasy.premierleague.com/drf/transfers";
                var response4 = requester.Get(url, ref cookies, out resp);
                DumpCookies(cookies);

                var teamID = "1733540";
                _logger.WriteDebugMessage("GET drf/my-team/" + teamID);
                url = "https://fantasy.premierleague.com/drf/my-team/" + teamID;
                var response6 = requester.Get(url, ref cookies, out resp);
                DumpCookies(cookies);


                return cookies;
            }
            catch (WebException e)
            {
                _logger.WriteErrorMessage("Authenticate - Error occurred", e);
            }
            catch (Exception e)
            {
                _logger.WriteErrorMessage("Authenticate - Error occurred", e);
            }

            return null;
        }


        public void DumpCookies(CookieContainer cookieContainer)
        {
            _logger.WriteDebugMessage($"Cookies:");
            DumpCookies(cookieContainer, new Uri("https://fantasy.premierleague.com/"));
            DumpCookies(cookieContainer, new Uri("https://users.premierleague.com/"));
            DumpCookies(cookieContainer, new Uri("https://premierleague.com/"));
        }

        public void DumpCookies(CookieContainer cookieContainer, Uri uri)
        {
            _logger.WriteDebugMessage($"Cookies @{uri}:");

            var cookies = cookieContainer.GetCookies(uri);
            foreach(var cookie in cookies.OfType<Cookie>())
            {
                var msg = $"{cookie.Name}: {cookie.Value}";
                _logger.WriteDebugMessage(msg);
            }
        }



        private class WebPageRequester
        {
            private const string _HEADERS_ACCEPT            = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8";
            private const string _HEADERS_ACCEPT_ENCODING   = "gzip, deflate";
            private const string _HEADERS_ACCEPT_LANGUAGE   = "en-US,en;q=0.8,sv;q=0.6";
            private const string _HEADERS_USER_AGENT        = "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36"; // just a dummy user agent that looks like a real browser

            private ILogger _logger;

            public WebPageRequester(ILogger logger)
            {
                _logger = logger;
            }

            public string Post(string url, string data, ref CookieContainer refCookies)
            {
                System.Net.HttpWebResponse resp;
                return Post(url, data, ref refCookies, out resp);
            }

            public string Post(string url, string data, ref CookieContainer refCookies, out System.Net.HttpWebResponse resp)
            {
                return MakeRequest(url, "application/x-www-form-urlencoded", "POST", data, ref refCookies, out resp);
            }

            public string Get(string url, ref CookieContainer refCookies)
            {
                System.Net.HttpWebResponse resp;
                return Get(url, ref refCookies, out resp);
            }

            public string Get(string url, ref CookieContainer refCookies, out System.Net.HttpWebResponse resp)
            {
                return MakeRequest(url, "text/html", "GET", null, ref refCookies, out resp);
            }

            #region Private Methods

            public string MakeRequest(string url, string contenttype, string method, string data, ref CookieContainer refCookies, out System.Net.HttpWebResponse resp, string referer = null)
            {
                // create new request
                var req = (HttpWebRequest)System.Net.HttpWebRequest.Create(url);

                // add headers as per browser
                req.Accept                      = _HEADERS_ACCEPT;
                req.UserAgent                   = _HEADERS_USER_AGENT;
                req.Headers["Accept-Encoding"]  = _HEADERS_ACCEPT_ENCODING;
                req.Headers["Accept-Language"]  = _HEADERS_ACCEPT_LANGUAGE; 
                req.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
                req.Headers["Upgrade-Insecure-Requests"] = "1";
                if (method == "POST")
                {
                    req.Referer = referer;
                    req.Headers["Origin"] = referer?.Trim('/');
                    req.Headers["Cache-Control"] = "max-age=0";
                }

                // Set method/content type
                req.ContentType = contenttype;
                req.Method = method;

                // Add cookies
                if (refCookies == null)
                    refCookies = new CookieContainer();
                req.CookieContainer = refCookies;
            
                if (data != null)
                {
                    _logger.WriteDebugMessage("WebPageRequester.MakeRequest - Sending data");

                    byte[] bytes = System.Text.Encoding.ASCII.GetBytes(data);
                    req.ContentLength = bytes.Length;

                    using (System.IO.Stream os = req.GetRequestStream())
                    {
                        os.Write(bytes, 0, bytes.Length); //Push it out there
                        os.Close();
                    }
                }

                _logger.WriteDebugMessage("WebPageRequester.MakeRequest - Reading response");

                resp = (HttpWebResponse)req.GetResponse();
                {
                    if (resp == null)
                        _logger.WriteErrorMessage("WebPageRequester.MakeRequest - No response received");
                    System.IO.StreamReader sr = new System.IO.StreamReader(resp.GetResponseStream());
                    var strResponse = sr.ReadToEnd().Trim();
                   // _logger.WriteInfoMessage("WebPageRequester.MakeRequest - Response: " + strResponse);
                    _logger.WriteDebugMessage("WebPageRequester.MakeRequest - Response Content Length: " + resp.ContentLength);
                    _logger.WriteDebugMessage("WebPageRequester.MakeRequest - Response Content Encoding: " + resp.ContentEncoding);
                    _logger.WriteDebugMessage("WebPageRequester.MakeRequest - Response Content Type: " + resp.ContentType);
                    _logger.WriteDebugMessage("WebPageRequester.MakeRequest - Response Character Set: " + resp.CharacterSet);
                    return strResponse;
                }
            }

            #endregion
        }
    }
}
