using System;
using System.Data.Entity;
using System.Web;
using Castle.MicroKernel.Registration;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.DataProtection;

[assembly: OwinStartup(typeof(Startup))]
namespace WebApp
{
	public class Startup
	{
		public void Configuration(IAppBuilder app)
		{
			ConfigureAuth(app);
		}

		private void ConfigureAuth(IAppBuilder app)
		{
			var container = DIContainer.GetConfiguredContainer();

			container.Register(
				Component
					.For<IAppBuilder>()
					.Instance(app),
				Component
					.For<ApplicationDbContext>()
					.DependsOn(Dependency.OnValue<string>("DefaultConnection"))
					.LifestyleTransient(),
				Component
					.For<IUserStore<WebAppUser>>()
					.ImplementedBy<UserStore<WebAppUser>>()
					.DependsOn(Dependency.OnComponent<DbContext, ApplicationDbContext>())
					.LifestyleTransient(),
				Component
					.For<ApplicationUserManager>()
					.UsingFactoryMethod(kernel =>
						CreateCustomUserManager(
							kernel.Resolve<IUserStore<WebAppUser>>(),
							kernel.Resolve<IAppBuilder>()))
					.LifestyleTransient(),
				Component
					.For<IRoleStore<IdentityRole, string>>()
					.ImplementedBy<RoleStore<IdentityRole>>()
					.DependsOn(Dependency.OnComponent<DbContext, ApplicationDbContext>())
					.LifestyleTransient(),
				Component
					.For<ApplicationRoleManager>()
					.LifestyleTransient(),
				Component
					.For<IAuthenticationManager>()
					.UsingFactoryMethod(kernel => HttpContext.Current.GetOwinContext().Authentication)
					.LifestyleTransient(),
				Component
					.For<ApplicationSignInManager>()
					.LifestyleTransient());

			app.CreatePerOwinContext(() => container.Resolve<ApplicationUserManager>());

			app.UseCookieAuthentication(new CookieAuthenticationOptions
			{
				AuthenticationType = DefaultAuthenticationTypes.ApplicationCookie,
				LoginPath = new PathString("/Account/Login"),
				Provider = new CookieAuthenticationProvider
				{
					OnValidateIdentity = SecurityStampValidator.OnValidateIdentity<ApplicationUserManager, WebAppUser>(
						validateInterval: TimeSpan.FromMinutes(15),
						regenerateIdentity: (manager, user) => user.GenerateUserIdentityAsync(manager))
				}
			});
		}

		private static ApplicationUserManager CreateCustomUserManager(
			IUserStore<WebAppUser> store,
			IAppBuilder appBuilder)
		{
			var manager = new ApplicationUserManager(store);

			manager.UserValidator = new UserValidator<WebAppUser>(manager)
			{
				AllowOnlyAlphanumericUserNames = true,
				RequireUniqueEmail = true
			};

			manager.PasswordValidator = new PasswordValidator
			{
				RequiredLength = Common.Constants.MinimumUserPasswordLength,
				RequireNonLetterOrDigit = false,
				RequireDigit = false,
				RequireLowercase = false,
				RequireUppercase = false
			};

			manager.UserLockoutEnabledByDefault = true;
			manager.DefaultAccountLockoutTimeSpan = Common.Constants.AccountLockoutTimeSpan;
			manager.MaxFailedAccessAttemptsBeforeLockout = Common.Constants.MaxFailedAccessAttemptsBeforeLockout;

			var dataProtectionProvider = appBuilder.GetDataProtectionProvider();
			if (dataProtectionProvider != null)
			{
				var dataProtector = dataProtectionProvider.Create("ASP.NET Identity");
				manager.UserTokenProvider = new DataProtectorTokenProvider<WebAppUser>(dataProtector);
			}

			return manager;
		}
	}
}
