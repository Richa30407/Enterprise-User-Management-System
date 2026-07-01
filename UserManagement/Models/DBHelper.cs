using Npgsql;
using System;
using System.Data;
using Microsoft.Extensions.Configuration;
using System.IO;

namespace UserManagement.Models
{
    public class DBHelper
    {
        private static readonly string connectionString;

        static DBHelper()
        {
            var configuration = new ConfigurationBuilder()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();

            var connStr = configuration.GetConnectionString("DefaultConnection") 
                          ?? configuration["DATABASE_URL"]
                          ?? Environment.GetEnvironmentVariable("DATABASE_URL")
                          ?? Environment.GetEnvironmentVariable("ConnectionStrings__DefaultConnection");

            if (string.IsNullOrEmpty(connStr))
            {
                connStr = "Host=localhost;Port=5432;Database=UserManagementDB;Username=postgres;Password=300407";
            }

            connectionString = ParsePostgresUriIfNeeded(connStr);
        }

        public NpgsqlConnection GetConnection()
        {
            return new NpgsqlConnection(connectionString);
        }

        private static string ParsePostgresUriIfNeeded(string uriString)
        {
            if (uriString.StartsWith("postgres://") || uriString.StartsWith("postgresql://"))
            {
                try
                {
                    var uri = new Uri(uriString);
                    var userInfo = uri.UserInfo.Split(':');
                    var username = userInfo[0];
                    var password = userInfo.Length > 1 ? userInfo[1] : "";
                    var host = uri.Host;
                    var port = uri.Port > 0 ? uri.Port : 5432;
                    var database = uri.AbsolutePath.TrimStart('/');

                    return $"Host={host};Port={port};Database={database};Username={username};Password={password};SSL Mode=Require;Trust Server Certificate=true;";
                }
                catch
                {
                    return uriString;
                }
            }
            return uriString;
        }
    }
}