using Microsoft.AspNetCore.Identity;
using System;

namespace UserManagement.Models
{
    public class ApplicationUser : IdentityUser<int>
    {
        public string FullName { get; set; } = string.Empty;
        public DateTime DOB { get; set; }
        public string Gender { get; set; } = string.Empty;
        public DateTime CreatedDate { get; set; } = DateTime.Now;
        public string? ResetToken { get; set; }
        public DateTime? ResetTokenExpiry { get; set; }
        public int RoleId { get; set; }
    }
}
