using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Principal;
using Microsoft.Owin;

namespace Snork.AspNet.DashboardBuilder
{
    /// <summary>
    /// </summary>
    public class UserAndRoleAuthorizationFilter : IDashboardAuthorizationFilter
    {
        private List<string> _roles = new List<string>();

        private List<string> _users = new List<string>();

        /// <summary>
        ///     Gets or sets the authorized roles.
        /// </summary>
        /// <value>
        ///     The roles string.
        /// </value>
        /// <remarks>Multiple role names can be specified using the comma character as a separator.</remarks>
        public string Roles
        {
            get => string.Join(",", _roles);
            set => _roles = SplitString(value);
        }

        /// <summary>
        ///     Gets or sets the authorized users.
        /// </summary>
        /// <value>
        ///     The users string.
        /// </value>
        /// <remarks>Multiple role names can be specified using the comma character as a separator.</remarks>
        public string Users
        {
            get => string.Join(",", _users);
            set => _users = SplitString(value);
        }

        /// <summary>
        /// </summary>
        /// <param name="dashboardContext"></param>
        /// <returns></returns>
        public bool Authorize(DashboardContext dashboardContext)
        {
            var owinDashboardContext = dashboardContext as OwinDashboardContext;
            var context = new OwinContext(owinDashboardContext.Environment);
            IPrincipal user = context.Authentication.User;

            if (user?.Identity == null || !user.Identity.IsAuthenticated)
            {
                return false;
            }

            if (_users.Any() && !_users.Contains(user.Identity.Name, StringComparer.OrdinalIgnoreCase))
            {
                return false;
            }

            if (_roles.Any() && !_roles.Any(user.IsInRole))
            {
                return false;
            }

            return true;
        }


        /// <summary>
        ///     Splits the string on commas and removes any leading/trailing whitespace from each result item.
        /// </summary>
        /// <param name="original">The input string.</param>
        /// <returns>An array of strings parsed from the input <paramref name="original" /> string.</returns>
        private static List<string> SplitString(string original)
        {
            if (string.IsNullOrWhiteSpace(original))
            {
                return new List<string>();
                ;
            }

            var split = from piece in original.Split(',')
                let trimmed = piece.Trim()
                where !string.IsNullOrWhiteSpace(trimmed)
                select trimmed;
            return split.ToList();
        }
    }
}