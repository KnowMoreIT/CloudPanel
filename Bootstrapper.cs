namespace CloudPanel
{
    using CloudPanel.Base.Config;
    using CloudPanel.Base.Models.Database;
    using CloudPanel.Code;
    using CloudPanel.Database.EntityFramework;
    using CloudPanel.Modules;
    using Database.EntityFramework.Migrations;
    using log4net;
    using log4net.Config;
    using Nancy;
    using Nancy.Authentication.Forms;
    using Nancy.Authentication.Stateless;
    using Nancy.Bootstrapper;
    using Nancy.Cryptography;
    using Nancy.TinyIoc;
    using System;
    using System.Linq;
    using System.Text;
    using System.Threading.Tasks;

    public class Bootstrapper : DefaultNancyBootstrapper
    {
        private static readonly ILog logger = LogManager.GetLogger(System.Reflection.MethodBase.GetCurrentMethod().DeclaringType);

        protected override void ApplicationStartup(Nancy.TinyIoc.TinyIoCContainer container, Nancy.Bootstrapper.IPipelines pipelines)
        {
            try
            {
#if DEBUG
                StaticConfiguration.DisableErrorTraces = false;
#else
                StaticConfiguration.DisableErrorTraces = true;
#endif

                // Enable the logger
                XmlConfigurator.Configure();

                // Increase the max json length
                logger.DebugFormat("Maximizing JSON length");
                Nancy.Json.JsonSettings.MaxJsonLength = Int32.MaxValue;

                // Load the settings
                logger.DebugFormat("Loading the settings");
                StaticSettings.LoadSettings();

                logger.DebugFormat("Configuring cryptography");
                CryptographyConfiguration cryptographyConfiguration = new CryptographyConfiguration(
                    new RijndaelEncryptionProvider(
                        new PassphraseKeyGenerator(Settings.EncryptedPassword, Encoding.ASCII.GetBytes(Settings.SaltKey))
                    ),
                    new DefaultHmacProvider(
                        new PassphraseKeyGenerator(Settings.EncryptedPassword, Encoding.ASCII.GetBytes(Settings.SaltKey))
                    )
                );

                // Enable cookie based sessions
                //logger.DebugFormat("Enabling cooking based sessions");
                //CookieBasedSessions.Enable(pipelines, cryptographyConfiguration);

                logger.DebugFormat("Configuring forms authentication");
                FormsAuthenticationConfiguration formsAuthConfiguration = new FormsAuthenticationConfiguration()
                {
                    CryptographyConfiguration = cryptographyConfiguration,
                    RedirectUrl = "~/",
                    UserMapper = container.Resolve<IUserMapper>()
                };
                FormsAuthentication.Enable(pipelines, formsAuthConfiguration);

                logger.DebugFormat("Settings CORS Enable");
                //AllowAccessToSite(ref pipelines);

                // Read licenses
                logger.DebugFormat("Reading pipelines");
                Licensing.ReadLicenses();

                // Initialize auditing
                logger.DebugFormat("Setting up pipeline after requests");
                pipelines.AfterRequest += (ctx) =>
                    {
                        if (ctx.Request.Method.Equals("GET"))
                        {
                            if (ctx.CurrentUser != null && ctx.Parameters.CompanyCode.HasValue)
                            {
                                Extensions.SetCompanyCode(ctx, ctx.Parameters.CompanyCode.Value);
                            }
                        }
                        else
                        {
                            Trace(ctx);
                        }
                    };

                // Update database
                logger.DebugFormat("Updating database");
                //UpdateDatabase();

                logger.DebugFormat("Done loading application");
            }
            catch (Exception ex)
            {
                logger.ErrorFormat("Error: " + ex.ToString());
                throw;
            }
        }

        /// <summary>
        /// For each request that is started
        /// </summary>
        /// <param name="container"></param>
        /// <param name="pipelines"></param>
        /// <param name="context"></param>
        protected override void RequestStartup(TinyIoCContainer container, IPipelines pipelines, NancyContext context)
        {
            logger.DebugFormat("Configuring stateless authentication");
            StatelessAuthenticationConfiguration statelessAuthConfiguration = new StatelessAuthenticationConfiguration(ctx =>
            {
                string apiKey = string.Empty;

                if (ctx.Request.Query.ApiKey.HasValue)
                {
                    apiKey = ctx.Request.Query.ApiKey.Value;
                    logger.DebugFormat("ApiKey {0} found in the query strings", apiKey);
                }

                if (ctx.Request.Form.ApiKey.HasValue)
                {
                    apiKey = ctx.Request.Form.ApiKey.Value;
                    logger.DebugFormat("ApiKey {0} found in the form values", apiKey);
                }

                if (string.IsNullOrEmpty(apiKey))
                    return null;

                return UserMapper.GetUserFromApiKey(apiKey, ctx);
            });
            StatelessAuthentication.Enable(pipelines, statelessAuthConfiguration);

            // Call Base?
            base.RequestStartup(container, pipelines, context);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="container"></param>
        protected override void ConfigureApplicationContainer(TinyIoCContainer container)
        {
            container.Register<IUserMapper, UserMapper>();
            container.Register<CloudPanelContext>((x, y) => string.IsNullOrEmpty(Settings.ConnectionString) ? null : new CloudPanelContext(Settings.ConnectionString));
        }

        /// <summary>
        /// Update to support localization
        /// </summary>
        protected override NancyInternalConfiguration InternalConfiguration
        {
            get
            {
                return NancyInternalConfiguration.WithOverrides(x => x.TextResource = typeof(CloudPanelLocalization));
                //return base.InternalConfiguration;
            }
        }

        /// <summary>
        /// Enable CORS
        /// </summary>
        /// <param name="pipelines"></param>
        private static void AllowAccessToSite(ref IPipelines pipelines)
        {
            pipelines.AfterRequest.AddItemToEndOfPipeline((ctx) =>
            {
                ctx.Response.WithHeader("Access-Control-Allow-Origin", "*")
                            .WithHeader("Access-Control-Allow-Methods", "POST,GET,DELETE,PUT,OPTIONS")
                            .WithHeader("Access-Control-Allow-Headers", "Accept, Origin, Content-type");
            });
        }

        /// <summary>
        /// Updates the database in the background
        /// </summary>
        private async void UpdateDatabase()
        {
            await Task.Run(() =>
            {
                try
                {
                    System.Data.Entity.Database.SetInitializer(new System.Data.Entity.MigrateDatabaseToLatestVersion<CloudPanelContext, Configuration>());

                    var configuration = new Configuration();
                    var migrator = new System.Data.Entity.Migrations.DbMigrator(configuration);
                    var pendingMigrations = migrator.GetPendingMigrations();

                    if (pendingMigrations.Count() > 0)
                    {
                        var pendingStr = String.Join(", ", pendingMigrations);
                        logger.InfoFormat("The following migrations were pending and attempting to update: {0}", pendingStr);
                        migrator.Update();
                    }
                    else
                    {
                        logger.InfoFormat("No pending database migrations are required");
                    }
                }
                catch (Exception ex)
                {
                    logger.ErrorFormat("Error updating database automatically: {0}", ex.ToString());
                }

                // Reload brandings after the update
                BrandingModule.LoadAllBrandings();
            });
        }

        /// <summary>
        /// Logs everything except for GET methods
        /// </summary>
        /// <param name="ctx"></param>
        private async void Trace(NancyContext ctx)
        {
            await Task.Run(() =>
            {
                CloudPanelContext db = null;
                try
                {
                    db = new CloudPanelContext(Settings.ConnectionString);
                    var sb = new StringBuilder();

                    if (ctx.Parameters.Count > 0)
                        foreach (string k in ctx.Parameters.Keys)
                            sb.AppendFormat("{0}: {1}||", k, ctx.Parameters[k].Value);

                    if (ctx.Request.Form.Count > 0)
                        foreach (string k in ctx.Request.Form.Keys)
                        {
                            if (k != "password" && k != "Password" && k != "pwd" && k != "Pwd") // Do not capture passwords in audit trace
                                sb.AppendFormat("{0}: {1}||", k, ctx.Request.Form[k].Value);
                        }

                    string str = sb.ToString();
                    if (str.EndsWith("||"))
                        str = str.Substring(0, str.Length - 2);

                    db.AuditTrace.Add(new AuditTrace()
                    {
                        TimeStamp = DateTime.Now,
                        IPAddress = ctx.Request.UserHostAddress,
                        Method = ctx.Request.Method,
                        Route = ctx.Request.Path,
                        Username = (ctx.CurrentUser == null ? string.Empty : ctx.CurrentUser.UserName),
                        Parameters = str,
                        CompanyCode = ctx.Parameters.CompanyCode.HasValue ? ctx.Parameters.CompanyCode : ""
                    });

                    db.SaveChanges();
                }
                catch (Exception ex)
                {
                    logger.ErrorFormat("Error after pipeline: {0}", ex.ToString());
                }
                finally
                {
                    if (db != null)
                        db.Dispose();
                }
            });
        }
    }
}