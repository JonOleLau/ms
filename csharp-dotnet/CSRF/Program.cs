using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace CSRF
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
                            endpoints.MapGet("/execute", async httpContext =>
                            {
                                string command = httpContext.Request.Query["command"];
                                string dangerousCommand = httpContext.Request.Query["dangerousCommand"];
                                if (!string.IsNullOrEmpty(command))
                                {
                                    Process process = new Process();
                                    process.StartInfo.FileName = "cmd.exe";
                                    process.StartInfo.Arguments = "/C " + command;
                                    process.StartInfo.RedirectStandardOutput = true;
                                    process.StartInfo.UseShellExecute = false;
                                    process.StartInfo.CreateNoWindow = true;
                                    process.Start();

                                    string output = process.StandardOutput.ReadToEnd();
                                    process.WaitForExit();

                                    await httpContext.Response.WriteAsync(output);
                                }
                                else if (!string.IsNullOrEmpty(dangerousCommand))
                                {
                                    Process process = new Process();
                                    process.StartInfo.FileName = "cmd.exe";
                                    process.StartInfo.Arguments = "/C " + dangerousCommand;
                                    process.StartInfo.RedirectStandardOutput = true;
                                    process.StartInfo.UseShellExecute = false;
                                    process.StartInfo.CreateNoWindow = true;
                                    process.Start();

                                    string output = process.StandardOutput.ReadToEnd();
                                    process.WaitForExit();

                                    await httpContext.Response.WriteAsync(output);
                                }
                                else
                                {
                                    await httpContext.Response.WriteAsync("Please provide a command or dangerousCommand query parameter.");
                                }
                            });
                            endpoints.MapGet("/account", async httpContext =>
                            {
                                string html = @"
                                    <html>
                                        <body>
                                            <form method='POST' action='http://localhost:5000/execute'>
                                                <input type='hidden' name='command' value='echo Account settings updated.'>
                                                <input type='submit' value='Update Account'>
                                            </form>
                                        </body>
                                    </html>";
                                await httpContext.Response.WriteAsync(html);
                            });
                            endpoints.MapPost("/execute", async httpContext =>
                            {
                                string command = httpContext.Request.Form["command"];
                                if (!string.IsNullOrEmpty(command))
                                {
                                    Process process = new Process();
                                    process.StartInfo.FileName = "cmd.exe";
                                    process.StartInfo.Arguments = "/C " + command;
                                    process.StartInfo.RedirectStandardOutput = true;
                                    process.StartInfo.UseShellExecute = false;
                                    process.StartInfo.CreateNoWindow = true;
                                    process.Start();

                                    string output = process.StandardOutput.ReadToEnd();
                                    process.WaitForExit();

                                    await httpContext.Response.WriteAsync(output);
                                }
                                else
                                {
                                    await httpContext.Response.WriteAsync("Please provide a command parameter.");
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
