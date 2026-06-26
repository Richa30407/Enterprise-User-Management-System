using Microsoft.AspNetCore.Identity;

namespace UserManagement.Models
{
    public class ApplicationRole : IdentityRole<int>
    {
        public ApplicationRole() { }
        public ApplicationRole(string roleName) : base(roleName) { }
    }
}