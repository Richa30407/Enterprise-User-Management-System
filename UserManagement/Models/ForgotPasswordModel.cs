using System.ComponentModel.DataAnnotations;

namespace UserManagement.Models
{
    public class ForgotPasswordModel
    {
        [Required(ErrorMessage = "Email Address is required")]
        [EmailAddress(ErrorMessage = "Invalid Email Address")]
        [Display(Name = "Email Address")]
        public string Email { get; set; } = string.Empty;
    }
}
