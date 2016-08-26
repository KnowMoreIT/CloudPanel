using CloudPanel.Base.Models.Database;
using Nancy.Security;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;

namespace CloudPanel
{
    public class AuthUser : ClaimsPrincipal
    {
        public AuthUser(ClaimsPrincipal principal) : base(principal)
        { }

        public string DisplayName => FindFirst(ClaimTypes.Name).Value;
    }

    public class AuthenticatedUser
    {
        private int _pageSize;

        /// <summary>
        /// User Guid in Active Directory
        /// </summary>
        public Guid UserGuid { get; set; }

        /// <summary>
        /// When the session expires
        /// </summary>
        public DateTime Expires { get; set; }

        /// <summary>
        /// Username of the user
        /// </summary>
        public string UserName { get; set; }

        /// <summary>
        /// Display Name of the user
        /// </summary>
        public string DisplayName { get; set; }

        /// <summary>
        /// The department the user belongs to
        /// </summary>
        public string Department { get; set; }

        /// <summary>
        /// The currently selected reseller code
        /// </summary>
        public string SelectedResellerCode { get; set; }

        /// <summary>
        /// The currently selected reseller codes name
        /// </summary>
        public string SelectedResellerName { get; set; }

        /// <summary>
        /// The currently selected company code
        /// </summary>
        public string SelectedCompanyCode { get; set; }

        /// <summary>
        /// The currently selected company codes name
        /// </summary>
        public string SelectedCompanyName { get; set; }

        /// <summary>
        /// The company code the user belongs to
        /// </summary>
        public string CompanyCode { get; set; }

        /// <summary>
        /// The reseller code the user belongs to
        /// </summary>
        public string ResellerCode { get; set; }

        /// <summary>
        /// Page size for the jQuery DataTables
        /// </summary>
        public int PageSize
        {
            get { return _pageSize > 0 ? _pageSize : 25; }
            set { _pageSize = value; }
        }

        /// <summary>
        /// The product ID for spam filtering. Will be 0 if spam is not enabled for the company
        /// </summary>
        public int SelectedCompanySpamProduct { get; set; }

        /// <summary>
        /// The security permissions for the user
        /// </summary>
        public UserRoles SecurityPermissions { get; set; }

        /// <summary>
        /// List of claims that the user has
        /// </summary>
        public IEnumerable<string> Claims { get; set; }

        /// <summary>
        /// Checks if the claims contain a certain value
        /// </summary>
        /// <param name="claimName"></param>
        /// <returns></returns>
        public bool HasClaim(string claimName)
        {
            return Claims != null &&
                   Claims.Any(x => x.Equals(claimName, StringComparison.CurrentCultureIgnoreCase) || 
                                   x.Equals("SuperAdmin", StringComparison.CurrentCultureIgnoreCase));
        }

        /// <summary>
        /// Get the number of milliseconds expiration
        /// </summary>
        /// <returns></returns>
        public double ExpiresinMilliseconds()
        {
            return Expires.Subtract(DateTime.Now).TotalMilliseconds;
        }
    }
}