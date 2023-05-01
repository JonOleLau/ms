using System;
using System.Diagnostics;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace Command_Injection
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
                        });
                    });
                })
                .Build();

            await host.RunAsync();
        }
    }
}
