using System.Threading.Tasks;

namespace UserManagement.Repositories
{
    public interface IEmailService
    {
        Task SendPasswordResetEmailAsync(string email, string username, string resetLink);
    }
}
