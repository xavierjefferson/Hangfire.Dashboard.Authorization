using System;
using System.Collections.Generic;

using Microsoft.Owin;
using Snork.AspNet.DashboardBuilder;
namespace Snork.AspNet.DashboardBuilder
{
    /// <summary>
    /// Authorize if a given user has a certain claim with a specified value.
    /// </summary>
    public class ClaimsBasedAuthorizationFilter : IDashboardAuthorizationFilter
    {
        private readonly string _type;
        private readonly string _value;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="type">Claim type</param>
        /// <param name="value">Claim value</param>
        /// <exception cref="ArgumentNullException"></exception>
        public ClaimsBasedAuthorizationFilter(string type, string value)
        {
            if (type == null) throw new ArgumentNullException("type");
            if (value == null) throw new ArgumentNullException("value");

            _type = type;
            _value = value;
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

            if (owinContext.Authentication.User == null)
                return false;

            return owinContext.Authentication.User.HasClaim(_type, _value);
        }
    }
}
