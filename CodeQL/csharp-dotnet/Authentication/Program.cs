using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Login_System
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var host = Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.ConfigureServices(services =>
                    {
                        services.AddRouting();
                    });

                    webBuilder.Configure((context, app) =>
                    {
                        app.UseRouting();
                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapGet("/login", async httpContext =>
                            {
                                string username = httpContext.Request.Query["username"];
                                string password = httpContext.Request.Query["password"];

                                if (username == "admin")
                                {
                                    httpContext.Response.Headers["authenticated"] = "authenticated";
                                    httpContext.Response.StatusCode = StatusCodes.Status200OK;
                                    await httpContext.Response.WriteAsync("Login successful");
                                }
                                else
                                {
                                    httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                                    await httpContext.Response.WriteAsync("Invalid username or password");
                                }
                            });

                            endpoints.MapGet("/home", async httpContext =>
                            {
                                string authenticated = httpContext.Request.Headers["authenticated"];

                                if (authenticated == "authenticated")
                                {
                                    httpContext.Response.StatusCode = StatusCodes.Status200OK;
                                    await httpContext.Response.WriteAsync("Welcome, admin! Here's the top secret information: ...");
                                }
                                else
                                {
                                    httpContext.Response.StatusCode = StatusCodes.Status401Unauthorized;
                                    await httpContext.Response.WriteAsync("You must be authenticated to access this page.");
                                }
                            });
                        });
                    });
                })
                .Build();

            await host.RunAsync();
        }
    }
}
