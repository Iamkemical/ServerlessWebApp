using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace WebApp
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
           services.AddRazorPages();

            var clientSecret = Configuration["AmazonCognito:ClientSecret"];
            var clientId = Configuration["AmazonCognito:ClientId"];
            var metadataAddress = Configuration["AmazonCognito:MetaDataAddress"];
            var logOutUrl = Configuration["AmazonCognito:LogOutUrl"];
            var baseUrl = Configuration["AmazonCognito:BaseUrl"];

            services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(options => options.Events.OnSigningIn = FilterGroupClaims)
            .AddOpenIdConnect(options =>
            {
                options.ResponseType = "code";
                options.MetadataAddress = metadataAddress;
                options.ClientId = clientId;
                options.ClientSecret = clientSecret;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.Scope.Add("email");
                options.Scope.Add("profile");
                options.Scope.Add("openid");
                options.Events = new OpenIdConnectEvents
                {
                    OnRedirectToIdentityProviderForSignOut = (context) =>
                    {
                        var logoutUri = logOutUrl;
                        logoutUri += $"?client_id={clientId}&logout_uri={baseUrl}";
                        context.Response.Redirect(logoutUri);
                        context.HandleResponse();
                        return Task.CompletedTask;
                    }
                };
            });
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapRazorPages();
            });
        }

        //Remove all the claims that are unrelated to our identity
        private static Task FilterGroupClaims(CookieSigningInContext context)
        {
            var principal = context.Principal;
            if (principal.Identity is ClaimsIdentity identity)
            {
                var unused = identity.FindAll(GroupsToRemove).ToList();
                unused.ForEach(c => identity.TryRemoveClaim(c));
            }
            return Task.FromResult(principal);
        }

        private static bool GroupsToRemove(Claim claim)
        {
            string[] _groupObjectIds = new string[] { "identities" };
            return claim.Type == "groups" && !_groupObjectIds.Contains(claim.Type);
        }

    }
}
