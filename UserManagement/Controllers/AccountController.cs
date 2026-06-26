using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Linq;
using System.Threading.Tasks;
using UserManagement.Models;
using UserManagement.Repositories;
using UserManagement.Services;

namespace UserManagement.Controllers
{
    public class AccountController : Controller
    {
        private readonly IUserRepository userRepo;
        private readonly IEmailService emailService;
        private readonly IAppLogger logger;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;
        private readonly RoleManager<ApplicationRole> roleManager;

        public AccountController(
            IUserRepository userRepo, 
            IEmailService emailService, 
            IAppLogger logger,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            RoleManager<ApplicationRole> roleManager)
        {
            this.userRepo = userRepo;
            this.emailService = emailService;
            this.logger = logger;
            this.userManager = userManager;
            this.signInManager = signInManager;
            this.roleManager = roleManager;
        }

        // GET: /Account/Register
        public IActionResult Register()
        {
            return View(new UserModel());
        }

        // POST: /Account/Register
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(UserModel user)
        {
            if (!ModelState.IsValid)
            {
                logger.LogWarning("Registration", "Register User", "Registration form validation failed.");
                return View(user);
            }

            try
            {
                // Check Duplicate Username beforehand
                var existingUserByName = await userManager.FindByNameAsync(user.Username);
                if (existingUserByName != null)
                {
                    ModelState.AddModelError("Username", "Username already exists.");
                    logger.LogWarning("Registration", "Register User", $"Duplicate username registration failure for username: {user.Username}");
                    return View(user);
                }

                // Check Duplicate Email beforehand
                var existingUserByEmail = await userManager.FindByEmailAsync(user.EmailId);
                if (existingUserByEmail != null)
                {
                    ModelState.AddModelError("EmailId", "Email ID already exists.");
                    logger.LogWarning("Registration", "Register User", $"Duplicate email registration failure for email: {user.EmailId}");
                    return View(user);
                }

                // Dynamic Role Assignment: Use role names instead of hardcoded Role IDs
                string roleName = "User"; // Default fallback
                if (user.RoleId == 1) roleName = "Admin";
                else if (user.RoleId == 2) roleName = "User";
                else if (user.RoleId == 3) roleName = "SuperAdmin";

                // Ensure the role exists in RoleManager
                if (!await roleManager.RoleExistsAsync(roleName))
                {
                    await roleManager.CreateAsync(new ApplicationRole(roleName));
                }

                var appUser = new ApplicationUser
                {
                    FullName = user.FullName,
                    UserName = user.Username,
                    Email = user.EmailId,
                    PhoneNumber = user.MobileNo,
                    DOB = user.DOB,
                    Gender = user.Gender,
                    CreatedDate = DateTime.Now,
                    RoleId = user.RoleId // Populate for backward compatibility
                };

                // Add default security stamp
                appUser.SecurityStamp = Guid.NewGuid().ToString();

                var result = await userManager.CreateAsync(appUser, user.Password);
                if (result.Succeeded)
                {
                    // Add user to role by name using RoleManager/UserManager
                    await userManager.AddToRoleAsync(appUser, roleName);

                    TempData["RegisteredName"] = user.FullName;
                    TempData["RegisteredUsername"] = user.Username;

                    logger.LogInfo("Registration", "Register User", $"User registered successfully: username: {user.Username}, email: {user.EmailId}");
                    return RedirectToAction("RegistrationSuccess");
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    logger.LogWarning("Registration", "Register User", $"Registration failed for username: {user.Username}");
                    return View(user);
                }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Registration failed : " + ex.Message);
                logger.LogError("Registration", "Register User", $"Registration failed for username: {user.Username}", ex);
                return View(user);
            }
        }

        // GET: /Account/RegistrationSuccess
        public IActionResult RegistrationSuccess()
        {
            if (TempData.Peek("RegisteredUsername") == null)
            {
                return RedirectToAction("Register");
            }
            return View();
        }

        // GET: /Account/Login
        public IActionResult Login()
        {
            string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            Random random = new();
            string captcha = new string(
                Enumerable.Repeat(chars, 6)
                .Select(s => s[random.Next(s.Length)])
                .ToArray());

            HttpContext.Session.SetString("CaptchaCode", captcha);
            ViewBag.Captcha = captcha;

            return View(new LoginModel());
        }

        // POST: /Account/Login
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginModel model)
        {
            string sessionCaptcha = HttpContext.Session.GetString("CaptchaCode") ?? "";

            if (!ModelState.IsValid)
            {
                ViewBag.Captcha = sessionCaptcha;
                logger.LogWarning("Login", "User Login", "Login form validation failed.");
                return View(model);
            }

            if (!model.CaptchaCode.Equals(sessionCaptcha))
            {
                ModelState.AddModelError("CaptchaCode", "Invalid Captcha.");

                string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
                Random random = new();
                string newCaptcha = new string(
                    Enumerable.Repeat(chars, 6)
                    .Select(s => s[random.Next(s.Length)])
                    .ToArray());

                HttpContext.Session.SetString("CaptchaCode", newCaptcha);
                ViewBag.Captcha = newCaptcha;

                logger.LogSecurity("Login", "User Login", $"Captcha verification failed for user login: {model.Username}");
                return View(model);
            }

            try
            {
                var user = await userManager.FindByNameAsync(model.Username);
                if (user == null)
                {
                    ModelState.AddModelError("", "Invalid Username or Password.");
                    ViewBag.Captcha = HttpContext.Session.GetString("CaptchaCode");
                    logger.LogSecurity("Login", "User Login", $"Failed login attempt: invalid username or password for: {model.Username}");
                    return View(model);
                }

                // Check Lockout
                if (await userManager.IsLockedOutAsync(user))
                {
                    ModelState.AddModelError("", "Account is locked out. Please try again after 5 minutes.");
                    ViewBag.Captcha = HttpContext.Session.GetString("CaptchaCode");
                    logger.LogSecurity("Login", "User Login", $"Blocked login attempt for locked out user: {model.Username}");
                    return View(model);
                }

                // Password Sign-in using SignInManager (supports account lockout)
                var result = await signInManager.PasswordSignInAsync(user, model.Password, isPersistent: false, lockoutOnFailure: true);

                if (result.Succeeded)
                {
                    // Reset Access Failed Count
                    await userManager.ResetAccessFailedCountAsync(user);

                    // Set Session variables ONLY for backward compatibility during migration
                    HttpContext.Session.SetInt32("UserId", user.Id);
                    HttpContext.Session.SetString("UserSession", user.UserName ?? string.Empty);
                    
                    var roles = await userManager.GetRolesAsync(user);
                    string sessionRole = "2"; // Default User (2)
                    if (roles.Contains("Admin")) sessionRole = "1";
                    else if (roles.Contains("SuperAdmin")) sessionRole = "3";
                    
                    HttpContext.Session.SetString("UserRole", sessionRole);

                    logger.LogInfo("Login", "User Login", $"User logged in successfully: username: {user.UserName}");
                    return RedirectToAction("Dashboard", "Home");
                }
                else if (result.IsLockedOut)
                {
                    ModelState.AddModelError("", "Account is locked out. Please try again after 5 minutes.");
                    ViewBag.Captcha = HttpContext.Session.GetString("CaptchaCode");
                    logger.LogSecurity("Login", "User Login", $"User locked out due to repeated failed logins: {model.Username}");
                    return View(model);
                }
                else
                {
                    ModelState.AddModelError("", "Invalid Username or Password.");
                    ViewBag.Captcha = HttpContext.Session.GetString("CaptchaCode");
                    logger.LogSecurity("Login", "User Login", $"Failed login attempt: invalid username or password for: {model.Username}");
                    return View(model);
                }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError("", "Login failed : " + ex.Message);
                logger.LogError("Login", "User Login", $"Login failed with exception for user: {model.Username}", ex);
                return View(model);
            }
        }

        // GET: /Account/ForgotPassword
        public IActionResult ForgotPassword()
        {
            return View(new ForgotPasswordModel());
        }

        // POST: /Account/ForgotPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordModel model)
        {
            if (!ModelState.IsValid)
            {
                logger.LogWarning("Password Recovery", "Request Link", "Forgot password form validation failed.");
                return View(model);
            }

            try
            {
                var user = await userManager.FindByEmailAsync(model.Email);
                if (user != null)
                {
                    // Generate Identity Password Reset Token
                    var token = await userManager.GeneratePasswordResetTokenAsync(user);

                    // Build dynamic verification link with token and email for lookup on reset
                    var resetLink = $"{Request.Scheme}://{Request.Host}{Url.Action("ResetPassword", "Account")}?token={Uri.EscapeDataString(token)}&email={Uri.EscapeDataString(user.Email ?? string.Empty)}";

                    // Send email
                    await emailService.SendPasswordResetEmailAsync(user.Email ?? string.Empty, user.FullName, resetLink);
                    logger.LogInfo("Password Recovery", "Request Link", $"Password reset link requested and generated for user ID: {user.Id}, email: {model.Email}");
                }
                else
                {
                    logger.LogWarning("Password Recovery", "Request Link", $"Password reset link requested for non-existent email: {model.Email}");
                }

                TempData["LinkSent"] = true;
                return View(new ForgotPasswordModel());
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "An error occurred: " + ex.Message);
                logger.LogError("Password Recovery", "Request Link", $"Failed password reset link request for email: {model.Email}", ex);
                return View(model);
            }
        }

        // GET: /Account/ResetPassword
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            if (string.IsNullOrEmpty(token) || string.IsNullOrEmpty(email))
            {
                ViewBag.TokenError = "The password reset token or email is missing. Please initiate a new password reset request.";
                logger.LogWarning("Password Recovery", "Verify Token", "Verify token request without token or email values.");
                return View(new ResetPasswordModel());
            }

            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                ViewBag.TokenError = "The password reset link is invalid. Please request a new password reset.";
                logger.LogWarning("Password Recovery", "Verify Token", $"Invalid reset attempt: User with email {email} not found.");
                return View(new ResetPasswordModel());
            }

            ViewBag.Username = user.UserName;
            logger.LogInfo("Password Recovery", "Verify Token", $"Reset token verification stage for user: {user.UserName}");
            return View(new ResetPasswordModel { Token = token });
        }

        // POST: /Account/ResetPassword
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordModel model, [FromQuery] string email)
        {
            if (string.IsNullOrEmpty(email))
            {
                ModelState.AddModelError(string.Empty, "Email address is missing.");
                return View(model);
            }

            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                ModelState.AddModelError(string.Empty, "User not found.");
                return View(model);
            }

            if (!ModelState.IsValid)
            {
                ViewBag.Username = user.UserName;
                logger.LogWarning("Password Recovery", "Reset Password", "Reset password form validation failed.");
                return View(model);
            }

            try
            {
                // Verify password is not reused
                var passwordHasher = HttpContext.RequestServices.GetRequiredService<IPasswordHasher<ApplicationUser>>();
                if (passwordHasher.VerifyHashedPassword(user, user.PasswordHash ?? string.Empty, model.Password) != PasswordVerificationResult.Failed)
                {
                    ModelState.AddModelError("Password", "New password cannot be the same as your current password.");
                    logger.LogWarning("Password Recovery", "Reset Password", $"Password reuse check failed: User ID {user.Id} attempted to reuse current password.");
                    ViewBag.Username = user.UserName;
                    return View(model);
                }

                var result = await userManager.ResetPasswordAsync(user, model.Token, model.Password);
                if (result.Succeeded)
                {
                    // Update Security Stamp after password changes/resets so previous sessions become invalid
                    await userManager.UpdateSecurityStampAsync(user);

                    logger.LogInfo("Password Recovery", "Reset Password", $"Password reset operation completed successfully for User ID: {user.Id}");
                    TempData["ResetSuccess"] = true;
                    ViewBag.Username = user.UserName;
                    return View(model);
                }
                else
                {
                    foreach (var error in result.Errors)
                    {
                        ModelState.AddModelError(string.Empty, error.Description);
                    }
                    logger.LogWarning("Password Recovery", "Reset Password", $"Password reset failed for User ID {user.Id}");
                    ViewBag.Username = user.UserName;
                    return View(model);
                }
            }
            catch (Exception ex)
            {
                ModelState.AddModelError(string.Empty, "Password reset failed: " + ex.Message);
                logger.LogError("Password Recovery", "Reset Password", $"Password reset operation failed for User ID: {user.Id}", ex);
                ViewBag.Username = user.UserName;
                return View(model);
            }
        }
    }
}