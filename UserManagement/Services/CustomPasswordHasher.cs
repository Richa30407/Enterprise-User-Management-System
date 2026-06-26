using Microsoft.AspNetCore.Identity;
using UserManagement.Models;

namespace UserManagement.Services
{
    public class CustomPasswordHasher : PasswordHasher<ApplicationUser>
    {
        public override PasswordVerificationResult VerifyHashedPassword(
            ApplicationUser user, string hashedPassword, string providedPassword)
        {
            if (string.IsNullOrEmpty(hashedPassword))
            {
                return PasswordVerificationResult.Failed;
            }

            // 1. Check if it's a BCrypt hash
            if (hashedPassword.StartsWith("$2a$") || hashedPassword.StartsWith("$2b$") || hashedPassword.StartsWith("$2y$"))
            {
                try
                {
                    if (BCrypt.Net.BCrypt.Verify(providedPassword, hashedPassword))
                    {
                        // Successfully verified, rehash needed to upgrade to standard Identity hashing
                        return PasswordVerificationResult.SuccessRehashNeeded;
                    }
                }
                catch
                {
                    // If BCrypt verification errors, proceed to other checks
                }
            }

            // 2. Legacy plain-text fallback (required for existing plain-text passwords in database)
            if (!hashedPassword.Contains("$"))
            {
                if (providedPassword == hashedPassword)
                {
                    return PasswordVerificationResult.SuccessRehashNeeded;
                }
            }

            // 3. Default ASP.NET Core Identity PasswordHasher verification
            return base.VerifyHashedPassword(user, hashedPassword, providedPassword);
        }
    }
}
