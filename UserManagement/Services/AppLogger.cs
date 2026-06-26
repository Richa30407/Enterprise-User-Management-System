using System;
using System.IO;
using Microsoft.AspNetCore.Http;

namespace UserManagement.Services
{
    public class AppLogger : IAppLogger
    {
        private readonly IHttpContextAccessor _httpContextAccessor;
        private static readonly object _fileLock = new object();
        private readonly string _logDirectory;

        public AppLogger(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
            _logDirectory = Path.Combine(Directory.GetCurrentDirectory(), "Logs");
            
            try
            {
                // Automatically create the Logs folder if it does not exist
                if (!Directory.Exists(_logDirectory))
                {
                    Directory.CreateDirectory(_logDirectory);
                }
            }
            catch
            {
                // Fail-safe
            }
        }

        public void Log(string module, string action, string status, string description, Exception? ex = null)
        {
            try
            {
                var context = _httpContextAccessor.HttpContext;
                
                string username = "N/A";
                string userIdStr = "N/A";
                string role = "N/A";
                string ipAddress = "N/A";

                if (context != null)
                {
                    username = context.Session.GetString("UserSession") ?? "Anonymous";
                    int? userId = context.Session.GetInt32("UserId");
                    if (userId.HasValue && userId.Value != 0)
                    {
                        userIdStr = userId.Value.ToString();
                    }
                    
                    string roleId = context.Session.GetString("UserRole") ?? "";
                    if (roleId == "1")
                    {
                        role = "Admin";
                    }
                    else if (roleId == "2")
                    {
                        role = "User";
                    }
                    else
                    {
                        role = "Guest";
                    }
                    
                    ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "N/A";
                    if (ipAddress == "::1")
                    {
                        ipAddress = "127.0.0.1";
                    }
                }

                string dateStr = DateTime.Now.ToString("dd-MM-yyyy");
                string timeStr = DateTime.Now.ToString("hh:mm:ss tt");

                // Construct Log Entry in the exact format required
                var entry = new System.Text.StringBuilder();
                entry.AppendLine("========================================================");
                entry.AppendLine($"Date : {dateStr}");
                entry.AppendLine($"Time : {timeStr}");
                entry.AppendLine($"User : {username}{(userIdStr != "N/A" ? $" (ID: {userIdStr})" : "")}");
                entry.AppendLine($"Role : {role}");
                entry.AppendLine($"IP Address : {ipAddress}");
                entry.AppendLine($"Module : {module}");
                entry.AppendLine($"Action : {action}");
                entry.AppendLine($"Status : {status}");
                entry.AppendLine($"Description : {description}");
                if (ex != null)
                {
                    entry.AppendLine($"Exception : {ex.Message}");
                    entry.AppendLine($"Stack Trace : {ex.StackTrace}");
                }
                entry.AppendLine("========================================================");

                // Write to daily log file thread-safely
                string logFile = Path.Combine(_logDirectory, $"log_{DateTime.Now:yyyy-MM-dd}.txt");
                lock (_fileLock)
                {
                    File.AppendAllText(logFile, entry.ToString());
                }
            }
            catch
            {
                // Ensure the application never crashes if logging fails (fail-safe)
            }
        }

        public void LogInfo(string module, string action, string description)
        {
            Log(module, action, "Success", description);
        }

        public void LogWarning(string module, string action, string description)
        {
            Log(module, action, "Warning", description);
        }

        public void LogError(string module, string action, string description, Exception? ex = null)
        {
            Log(module, action, "Error", description, ex);
        }

        public void LogSecurity(string module, string action, string description, Exception? ex = null)
        {
            Log(module, action, "Security Warning/Failure", description, ex);
        }
    }
}
