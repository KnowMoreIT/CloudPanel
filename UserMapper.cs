using CloudPanel.ActiveDirectory;
using CloudPanel.Base.Config;
using CloudPanel.Base.Models.Database;
using CloudPanel.Database.EntityFramework;
using log4net;
using Nancy;
using Nancy.Authentication.Forms;
using Nancy.Security;
using System;
using System.Collections.Generic;
using System.Linq;

namespace CloudPanel
{

    public class UserMapper : IUserMapper
    {
        private static readonly ILog logger = log4net.LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        public static List<AuthenticatedUser> loggedInUsers = new List<AuthenticatedUser>();

        /// <summary>
        /// Increasese the user session timeout
        /// </summary>
        /// <param name="identifier"></param>
        /// <param name="hours"></param>
        public static async void IncreaseUserSession(Guid identifier, double minutes)
        {
            try
            {
                using (CloudPanelContext db = new CloudPanelContext(Settings.ConnectionString))
                {
                    cp_Sessions session = db.cp_Sessions.Where(x => x.UserGuid == identifier)
                                                        .Where(x => x.Expires >= DateTime.Now)
                                                        .FirstOrDefault();

                    // If session isn't found then ignore
                    if (session != null)
                    {
                        // Update the expires date (we only care if they are idle)
                        session.Expires = DateTime.Now.AddMinutes(minutes);
                        await db.SaveChangesAsync();
                    }
                }
            }
            catch (Exception ex)
            {
                logger.ErrorFormat("Error increasing user session timeout for {0}: {1}", identifier, ex.ToString());
            }
        }

        /// <summary>
        /// Retrieve the user's session from the SQL database
        /// </summary>
        /// <param name="identifier"></param>
        /// <param name="context"></param>
        /// <returns></returns>
        public IUserIdentity GetUserFromIdentifier(Guid identifier, NancyContext context)
        {
            try
            {
                using (CloudPanelContext db = new CloudPanelContext(Settings.ConnectionString))
                {
                    cp_Sessions session = db.cp_Sessions.Where(x => x.UserGuid == identifier)
                                                        .Where(x => x.Expires >= DateTime.Now)
                                                        .FirstOrDefault();

                    // Return null if it doesn't exit
                    if (session == null)
                        return null;

                    // Update the expires date (we only care if they are idle)
                    IncreaseUserSession(identifier, 120);

                    // Otherwise return the Authenticated User object
                    return new AuthenticatedUser()
                    {
                        UserGuid = identifier,
                        UserName = session.Username,
                        Expires = session.Expires,
                        DisplayName = session.DisplayName,
                        CompanyCode = session.CompanyCode,
                        ResellerCode = session.ResellerCode,
                        SelectedCompanyCode = session.SelectedCompanyCode,
                        SelectedCompanyName = session.SelectedCompanyName,
                        SelectedResellerCode = session.SelectedResellerCode,
                        SelectedResellerName = session.SelectedResellerName,
                        Department = session.Department,
                        Claims = session.Claims.Split(','),
                        PageSize = 25,
                        SelectedCompanySpamProduct = 0
                    };
                }
            }
            catch (Exception ex)
            {
                logger.ErrorFormat("Error getting user from identifier {0}: {1}", identifier, ex.ToString());
                return null;
            }
        }

        /// <summary>
        /// Validates a user's credentials
        /// </summary>
        /// <param name="username"></param>
        /// <param name="password"></param>
        /// <returns></returns>
        public static cp_Sessions ValidateUser(string username, string password, bool rememberMe = false)
        {
            ADUsers user = null;
            CloudPanelContext db = null;
            try
            {
                // Initialize Active Directory and Database connections
                user = new ADUsers(Settings.Username, Settings.DecryptedPassword, Settings.PrimaryDC);
                db = new CloudPanelContext(Settings.ConnectionString);
                db.Database.Connection.Open();

                Users authenticatedUser = user.AuthenticateQuickly(username, password);
                if (authenticatedUser == null)
                    throw new Exception("Login failed. Please try again or contact support.");

                // Check if the user is already logged in or not
                cp_Sessions session = db.cp_Sessions.Where(x => x.Username == username && x.Expires >= DateTime.Now).FirstOrDefault();
                if (session == null)
                {
                    logger.DebugFormat("The user {0} is not cached. Adding to logged in users", username);
                    session = new cp_Sessions();
                    session.UserGuid = authenticatedUser.UserGuid;
                    session.Username = authenticatedUser.UserPrincipalName;
                    session.DisplayName = authenticatedUser.DisplayName;
                    session.Start = DateTime.Now;
                    session.Expires = rememberMe == true ? DateTime.Now.AddHours(8) : DateTime.Now.AddHours(2);

                    db.cp_Sessions.Add(session);
                }
                else
                    session.Expires = rememberMe == true ? DateTime.Now.AddHours(8) : DateTime.Now.AddHours(2); // If the user logs in while they are already logged in then append a day to their session

                // Check if the user is a super admin or not
                List<string> claims = new List<string>();
                foreach (string memberOf in authenticatedUser.MemberOf)
                {
                    logger.DebugFormat("Checking group {0} against {1}", memberOf, Settings.SuperAdminsAsString);
                    bool isSuperAdmin = Settings.SuperAdmins.Any(x => x.Equals(memberOf, StringComparison.CurrentCultureIgnoreCase));
                    if (isSuperAdmin)
                    {
                        claims.Add("SuperAdmin");
                        logger.DebugFormat("Adding claim SuperAdmin to the user {0}.", session.Username);
                        break;
                    }
                }

                // Query the database to find the SQL user if the user exists
                var sqlUser = (from d in db.Users
                               join c in db.Companies on d.CompanyCode equals c.CompanyCode into c1
                               from company in c1.DefaultIfEmpty()
                               join r in db.Companies on company.ResellerCode equals r.CompanyCode into r1
                               from reseller in r1.DefaultIfEmpty()
                               join p in db.UserRoles on d.RoleID equals p.RoleID into p1
                               from permission in p1.DefaultIfEmpty()
                               join u in db.User_Profile on d.ID equals u.UserID into u1
                               from profile in u1.DefaultIfEmpty()
                               where d.UserPrincipalName == session.Username
                               select new
                               {
                                   CompanyCode = d.CompanyCode,
                                   CompanyName = company.CompanyName,
                                   ResellerCode = company.ResellerCode,
                                   ResellerName = reseller.CompanyName,
                                   IsResellerAdmin = d.IsResellerAdmin,
                                   IsCompanyAdmin = d.IsCompanyAdmin,
                                   UserRole = permission,
                                   Profile = profile,
                                   Department = d.Department
                               }).FirstOrDefault();

                if (sqlUser != null)
                {
                    // Add values
                    session.ResellerCode = sqlUser.ResellerCode;
                    session.SelectedResellerCode = sqlUser.ResellerCode;
                    session.SelectedResellerName = sqlUser.ResellerName;
                    session.CompanyCode = sqlUser.CompanyCode;
                    session.SelectedCompanyCode = sqlUser.CompanyCode;
                    session.SelectedCompanyName = sqlUser.CompanyName;
                    session.Department = sqlUser.Department;
                    session.PageSize = sqlUser.Profile == null ? 25 : sqlUser.Profile.PageSize;

                    if (sqlUser.UserRole != null)
                    {
                        if (sqlUser.UserRole.IsReseller == true)
                        {
                            claims.Add("ResellerAdmin");
                            logger.InfoFormat("Adding claim ResellerAdmin to {0}", session.Username);
                        }

                        if (sqlUser.IsCompanyAdmin == true)
                        {
                            claims.Add("CompanyAdmin");
                            logger.InfoFormat("Adding claim CompanyAdmin to {0}", session.Username);
                        }

                        foreach (var p in sqlUser.UserRole.GetType().GetProperties())
                        { 
                            // Loop through each property and set the value if it is true on the user role data
                            if (p.PropertyType == typeof(bool))
                            {
                                bool isTrue = (bool)p.GetValue(sqlUser.UserRole, null);
                                if (isTrue)
                                {
                                    claims.Add(p.Name);
                                    logger.InfoFormat("Adding claim {0} to user {1}", p.Name, session.Username);
                                }
                            }
                        }
                    }
                    else
                        logger.DebugFormat("User role was not found for {0}", session.Username);
                }

                logger.DebugFormat("Setting the claims for user {0} to {1}", username, String.Join(", ", claims));
                session.Claims = String.Join(",", claims);
                db.SaveChanges();

                return session;
            }
            catch (Exception ex)
            {
                logger.ErrorFormat("Error logging in user {0}: {1}", username, ex.ToString());
                throw;
            }
            finally
            {
                if (db != null)
                    db.Dispose();

                if (user != null)
                    user.Dispose();
            }
        }

        /// <summary>
        /// Gets the user from the API key
        /// </summary>
        /// <param name="apiKey"></param>
        /// <returns></returns>
        public static IUserIdentity GetUserFromApiKey(string apiKey, NancyContext context)
        {
            CloudPanelContext db = null;
            try
            {
                logger.DebugFormat("Getting API user with key {0}", apiKey);
                db = new CloudPanelContext(Settings.ConnectionString);

                var user = db.Users.Include("ApiKey")
                                   .Include("Role")
                                   .Where(x => x.ApiKey.Key == apiKey)
                                   .Single();

                if (user == null || user.ApiKey == null)
                    return null;
                else
                {
                    logger.DebugFormat("API user was found in the database: {0}", user.UserPrincipalName);

                    // Validate the IP addresses match
                    string[] ipAddresses = user.ApiKey.IPAddress.Split(new char[] { ',' }, StringSplitOptions.RemoveEmptyEntries);
                    if (!ipAddresses.Contains(context.Request.UserHostAddress))
                    {
                        logger.WarnFormat("API connection from {0} was refused because IP {1} was not found in allowed IP addresses: {2}", user.UserPrincipalName, context.Request.UserHostAddress, String.Join(",", ipAddresses));
                        return null;
                    }

                    // Create object
                    var authUser = new AuthenticatedUser();
                    authUser.UserGuid = user.UserGuid;
                    authUser.UserName = user.UserPrincipalName;
                    authUser.CompanyCode = user.CompanyCode;
                    authUser.SelectedCompanyCode = user.CompanyCode;
                    authUser.DisplayName = user.DisplayName;
                    authUser.SecurityPermissions = user.Role;
                    authUser.Department = user.Department;

                    // Add claims to the user role
                    var claims = new List<string>();
                    foreach (var p in user.Role.GetType().GetProperties())
                    {
                        if (p.PropertyType == typeof(bool))
                        {
                            if ((bool)p.GetValue(user.Role, null))
                            {
                                claims.Add(p.Name);
                                logger.DebugFormat("API user {0} was added claim {1}", user.UserPrincipalName, p.Name);
                            }
                        }
                    }

                    // See if the user is a super admin
                    if (user.ApiKey.SuperAdmin)
                        claims.Add("SuperAdmin");

                    // Set the claims of the user
                    authUser.Claims = claims;

                    logger.DebugFormat("Returning API user {0}", user.UserPrincipalName);
                    return authUser;
                }
            }
            catch (Exception ex)
            {
                logger.ErrorFormat("Error logging user in with api key {0}: {1}", apiKey, ex.ToString());
                return null;
            }
            finally
            {
                if (db != null)
                    db.Dispose();
            }
        }

        /// <summary>
        /// Checks if the user contains any claims or not
        /// </summary>
        /// <param name="guid"></param>
        /// <returns></returns>
        public static bool ContainsClaims(Guid guid)
        {
            cp_Sessions session = new CloudPanelContext(Settings.ConnectionString)
                                                       .cp_Sessions
                                                       .Where(x => x.UserGuid == guid)
                                                       .Where(x => x.Expires >= DateTime.Now)
                                                       .FirstOrDefault();
            if (session == null)
                return false;

            if (string.IsNullOrEmpty(session.Claims))
                return false;

            return true;
        }
    }
}