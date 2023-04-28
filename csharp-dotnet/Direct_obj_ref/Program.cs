using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System.Collections.Generic;
using System.Data.SqlClient;
using System.Threading.Tasks;

namespace Login_System
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var users = new List<User>()
            {
                new User() { Username = "Alice", Password = "1234" },
                new User() { Username = "Bob", Password = "5678" },
                new User() { Username = "Charlie", Password = "9012" }
            };

            var orders = new List<Order>()
            {
                new Order() { OrderID = 1, CustomerID = "ALFKI", ProductName = "IPhone" },
                new Order() { OrderID = 2, CustomerID = "ALFKI", ProductName = "Samsung" },
                new Order() { OrderID = 3, CustomerID = "ANATR", ProductName = "Apple" },
                new Order() { OrderID = 4, CustomerID = "ANATR", ProductName = "MacBook" },
                new Order() { OrderID = 5, CustomerID = "ALFKI", ProductName = "Android" }
            };

            var host = Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.ConfigureServices(services =>
                    {
                        services.AddRouting();
                    });

                    webBuilder.Configure(app =>
                    {
                        app.UseRouting();

                        app.UseEndpoints(endpoints =>
                        {
                            endpoints.MapGet("/orders", async context =>
                            {
                                string username = context.Request.Query["username"];
                                string password = context.Request.Query["password"];

                                // Find user in the list
                                var user = users.Find(u => u.Username == username && u.Password == password);

                                // If user not found, return 401 Unauthorized status code
                                if (user == null)
                                {
                                    context.Response.StatusCode = 401;
                                    await context.Response.WriteAsync("Unauthorized");
                                    return;
                                }

                                // Find orders for the customer
                                var customerOrders = orders.FindAll(o => o.CustomerID == context.Request.Query["id"]);

                                // Write orders to response
                                foreach (var order in customerOrders)
                                {
                                    await context.Response.WriteAsync($"<p>Order ID: {order.OrderID}, Customer ID: {order.CustomerID}, Product Name: {order.ProductName}</p>");
                                }
                            });
                        });
                    });
                })
                .Build();

            await host.RunAsync();
        }
    }

    public class User
    {
        public string Username { get; set; }
        public string Password { get; set; }
    }

    public class Order
    {
        public int OrderID { get; set; }
        public string CustomerID { get; set; }
        public string ProductName { get; set; }
    }
}
