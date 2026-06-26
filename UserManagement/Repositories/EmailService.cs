using System;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;
using Microsoft.Extensions.Configuration;

namespace UserManagement.Repositories
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _config;

        public EmailService(IConfiguration config)
        {
            _config = config;
        }

        public async Task SendPasswordResetEmailAsync(string email, string username, string resetLink)
        {
            string emailSubject = "Password Reset Request - User Management Portal";
            string emailBody = $@"
Hello {username},

We received a request to reset your password. 
To complete this request, please click the link below (valid for 15 minutes):

{resetLink}

If you did not request a password reset, please ignore this email.

Best regards,
User Management Portal Team
";

            // 1. Log to Local File for Easy Offline Testing/Verification
            try
            {
                string logDir = Path.Combine(Directory.GetCurrentDirectory(), "wwwroot");
                if (!Directory.Exists(logDir))
                {
                    Directory.CreateDirectory(logDir);
                }
                string logPath = Path.Combine(logDir, "sent_emails.log");
                string logContent = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] TO: {email} | USERNAME: {username}\nSUBJECT: {emailSubject}\nBODY:\n{emailBody}\n----------------------------------------------------------------------\n\n";
                await File.AppendAllTextAsync(logPath, logContent);
                Console.WriteLine($"[EmailService] Password reset email logged to: {logPath}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[EmailService] Failed to write log to file: {ex.Message}");
            }

            // 2. Attempt SMTP Delivery (if configured)
            try
            {
                string smtpHost = _config["Smtp:Host"] ?? string.Empty;
                if (!string.IsNullOrEmpty(smtpHost))
                {
                    int smtpPort = int.Parse(_config["Smtp:Port"] ?? "587");
                    string smtpUser = _config["Smtp:Username"] ?? string.Empty;
                    string smtpPass = _config["Smtp:Password"] ?? string.Empty;
                    string smtpFrom = _config["Smtp:FromAddress"] ?? "no-reply@usermanagement.com";

                    using var client = new SmtpClient(smtpHost, smtpPort)
                    {
                        Credentials = new NetworkCredential(smtpUser, smtpPass),
                        EnableSsl = true
                    };

                    var mailMessage = new MailMessage
                    {
                        From = new MailAddress(smtpFrom, "User Management Portal"),
                        Subject = emailSubject,
                        Body = emailBody,
                        IsBodyHtml = false
                    };
                    mailMessage.To.Add(email);

                    await client.SendMailAsync(mailMessage);
                    Console.WriteLine($"[EmailService] Password reset email successfully sent to {email} via SMTP.");
                }
                else
                {
                    Console.WriteLine("[EmailService] SMTP host is not configured. Email was logged locally only.");
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[EmailService] SMTP sending failed: {ex.Message}");
            }
        }
    }
}
