using Microsoft.AspNetCore.Mvc;
using UserManagement.Models;
using Npgsql;
using System;
using Microsoft.AspNetCore.Http;

namespace UserManagement.Controllers
{
    public class AccountController : Controller
    {
        private readonly DBHelper db = new DBHelper();

        // GET: /Account/Register
        public IActionResult Register()
        {
            return View(new UserModel());
        }

        // POST: /Account/Register
        [HttpPost]
        public IActionResult Register(UserModel user)
        {
            if (!ModelState.IsValid)
            {
                return View(user);
            }

            using (NpgsqlConnection con = db.GetConnection())
            {
                con.Open();

                // Check for duplicate username
                string checkQuery = "SELECT COUNT(*) FROM UserMaster WHERE Username = @Username";
                using (NpgsqlCommand checkCmd = new NpgsqlCommand(checkQuery, con))
                {
                    checkCmd.Parameters.AddWithValue("@Username", user.Username);
                    int count = Convert.ToInt32(checkCmd.ExecuteScalar());

                    if (count > 0)
                    {
                        ModelState.AddModelError("Username", "Username already exists");
                        return View(user);
                    }
                }

                // Insert new record into database
                string insertQuery = @"INSERT INTO UserMaster
                (FullName, Username, Password, EmailId, MobileNo, DOB, RoleId, Gender, CreatedDate)
                VALUES
                (@FullName, @Username, @Password, @EmailId, @MobileNo, @DOB, @RoleId, @Gender, CURRENT_TIMESTAMP)";

                using (NpgsqlCommand cmd = new NpgsqlCommand(insertQuery, con))
                {
                    cmd.Parameters.AddWithValue("@FullName", user.FullName);
                    cmd.Parameters.AddWithValue("@Username", user.Username);
                    cmd.Parameters.AddWithValue("@Password", user.Password);
                    cmd.Parameters.AddWithValue("@EmailId", user.EmailId);
                    cmd.Parameters.AddWithValue("@MobileNo", user.MobileNo);
                    cmd.Parameters.AddWithValue("@DOB", user.DOB);
                    cmd.Parameters.AddWithValue("@RoleId", user.RoleId);
                    cmd.Parameters.AddWithValue("@Gender", user.Gender);

                    cmd.ExecuteNonQuery();
                }
                con.Close();
            }

            TempData["SuccessMessage"] = "Registration Successful! Please Login.";
            return RedirectToAction("Login", "Account");
        }

        // GET: /Account/Login
        public IActionResult Login()
        {
            return View(new LoginModel());
        }

        // POST: /Account/Login
        [HttpPost]
        public IActionResult Login(LoginModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            using (NpgsqlConnection con = db.GetConnection())
            {
                con.Open();

                string query = @"SELECT UserId, Username, RoleId 
                                 FROM UserMaster 
                                 WHERE Username = @Username AND Password = @Password";

                using (NpgsqlCommand cmd = new NpgsqlCommand(query, con))
                {
                    cmd.Parameters.AddWithValue("@Username", model.Username);
                    cmd.Parameters.AddWithValue("@Password", model.Password);

                    using (NpgsqlDataReader reader = cmd.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            // Strictly handling null conversion using string casting to satisfy CS8604 compiler check
                            string sessionUser = reader["Username"] != DBNull.Value ? Convert.ToString(reader["Username"]) ?? "" : "";
                            string sessionRole = reader["RoleId"] != DBNull.Value ? Convert.ToString(reader["RoleId"]) ?? "" : "";

                            HttpContext.Session.SetString("UserSession", sessionUser);
                            HttpContext.Session.SetString("UserRole", sessionRole);

                            return RedirectToAction("Dashboard", "Home");
                        }
                        else
                        {
                            ModelState.AddModelError(string.Empty, "Invalid Username or Password");
                        }
                    }
                }
                con.Close();
            }

            return View(model);
        }
    }
}