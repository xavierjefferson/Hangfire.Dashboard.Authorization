using System;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using Microsoft.Owin;

namespace Snork.AspNet.DashboardBuilder
{
    /// <summary>
    ///     Represents dashboard authorization filter for basic authentication.
    /// </summary>
    /// <remarks>If you are using this together with OWIN security, configure dashboard BEFORE OWIN security configuration.</remarks>
    public class BasicAuthAuthorizationFilter : IDashboardAuthorizationFilter
    {
        private readonly BasicAuthAuthorizationFilterOptions _options;

        private readonly string _applicationName;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="applicationName">A short name for your application.</param>
        public BasicAuthAuthorizationFilter(string applicationName)
            : this(new BasicAuthAuthorizationFilterOptions(), applicationName)
        {
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="options"></param>
        /// <param name="applicationName">A short name for your application.</param>
        public BasicAuthAuthorizationFilter(BasicAuthAuthorizationFilterOptions options, string applicationName)
        {
            _options = options;
            _applicationName = applicationName;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="dashboardContext"></param>
        /// <returns></returns>
        public bool Authorize(DashboardContext dashboardContext)
        {
            var owinDashboardContext = dashboardContext as OwinDashboardContext;
            var owinContext = new OwinContext(owinDashboardContext.Environment);


            if (_options.SslRedirect && !owinContext.Request.IsSecure)
            {
                owinContext.Response.OnSendingHeaders(state =>
                {
                    var redirectUri = new UriBuilder("https", owinContext.Request.Uri.Host, 443,
                        owinContext.Request.Uri.PathAndQuery).ToString();

                    owinContext.Response.StatusCode = 301;
                    owinContext.Response.Redirect(redirectUri);
                }, null);
                return false;
            }

            if (_options.RequireSsl && !owinContext.Request.IsSecure)
            {
                owinContext.Response.Write(string.Format("Secure connection is required to access the {0} dashboard.",
                    _applicationName));
                return false;
            }

            var header = owinContext.Request.Headers["Authorization"];

            if (!string.IsNullOrWhiteSpace(header) )
            {
                var authValues = AuthenticationHeaderValue.Parse(header);

                if ("Basic".Equals(authValues.Scheme, StringComparison.InvariantCultureIgnoreCase))
                {
                    var parameter = Encoding.UTF8.GetString(Convert.FromBase64String(authValues.Parameter));
                    var parts = parameter.Split(':');

                    if (parts.Length > 1)
                    {
                        var login = parts[0];
                        var password = parts[1];

                        if (string.IsNullOrWhiteSpace(login) == false && string.IsNullOrWhiteSpace(password) == false)
                        {
                            return _options
                                       .Users
                                       .Any(user => user.Validate(login, password, _options.LoginCaseSensitive))
                                   || Challenge(owinContext);
                        }
                    }
                }
            }

            return Challenge(owinContext);
        }


        private bool Challenge(OwinContext context)
        {
            context.Response.StatusCode = 401;
            context.Response.Headers.Append("WWW-Authenticate",
                string.Format("Basic realm=\"{0} Dashboard\"", _applicationName));

            context.Response.Write("Authentication is required.");

            return false;
        }
    }
}