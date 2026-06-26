using System.ComponentModel.DataAnnotations;

namespace UserManagement.Models
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Username is required")]
        [StringLength(20,
            MinimumLength = 3,
            ErrorMessage = "Username must be between 3 and 20 characters")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Password is required")]
        [DataType(DataType.Password)]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Captcha is required")]
        public string CaptchaCode { get; set; } = string.Empty;
    }
}