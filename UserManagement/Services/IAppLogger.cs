using System;

namespace UserManagement.Services
{
    public interface IAppLogger
    {
        void Log(string module, string action, string status, string description, Exception? ex = null);
        void LogInfo(string module, string action, string description);
        void LogWarning(string module, string action, string description);
        void LogError(string module, string action, string description, Exception? ex = null);
        void LogSecurity(string module, string action, string description, Exception? ex = null);
    }
}
