using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Npgsql;
using System;
using System.Collections.Generic;
using UserManagement.Models;

namespace UserManagement.Controllers
{
    public class HomeController : Controller
    {
        private readonly DBHelper db = new DBHelper();

        // GET: /Home/Dashboard
        public IActionResult Dashboard() 
        {
            // 1. Check if the user session exists
            if (HttpContext.Session.GetString("UserSession") == null)
            {
                return RedirectToAction("Login", "Account");
            }

            string username = HttpContext.Session.GetString("UserSession") ?? "";
            string roleId = HttpContext.Session.GetString("UserRole") ?? "";

            ViewBag.Username = username;

            // 2. If the user is an ADMIN (RoleId == "1")
            if (roleId == "1")
            {
                List<UserModel> allUsers = new List<UserModel>();

                using (NpgsqlConnection con = db.GetConnection())
                {
                    con.Open();

                    // Query to fetch all registered normal users (RoleId = 2)
                    string query = "SELECT DISTINCT FullName, Username, EmailId, MobileNo FROM UserMaster WHERE RoleId = 2";

                    using (NpgsqlCommand cmd = new NpgsqlCommand(query, con))
                    {
                        using (NpgsqlDataReader reader = cmd.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                allUsers.Add(new UserModel
                                {
                                    FullName = reader["FullName"] != DBNull.Value ? reader["FullName"].ToString() ?? "" : "",
                                    Username = reader["Username"] != DBNull.Value ? reader["Username"].ToString() ?? "" : "",
                                    EmailId = reader["EmailId"] != DBNull.Value ? reader["EmailId"].ToString() ?? "" : "",
                                    MobileNo = reader["MobileNo"] != DBNull.Value ? reader["MobileNo"].ToString() ?? "" : ""
                                });
                            }
                        }
                    }
                    con.Close();
                }

                // Open Admin Dashboard view with user data list
                return View("AdminDashboard", allUsers);
            }

            // 3. If the user is a normal USER (RoleId == "2")
            return View("UserDashboard");
        }

        // Action to handle application logout
        public IActionResult Logout()
        {
            HttpContext.Session.Clear();
            return RedirectToAction("Login", "Account");
        }
    }
}