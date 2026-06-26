using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Npgsql;
using Dapper;
using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using UserManagement.Models;
using UserManagement.Repositories;
using UserManagement.Services;

namespace UserManagement.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly DBHelper db = new DBHelper();
        private readonly IUserRepository userRepo;
        private readonly IWebHostEnvironment env;
        private readonly IAppLogger logger;
        private readonly UserManager<ApplicationUser> userManager;
        private readonly SignInManager<ApplicationUser> signInManager;

        public HomeController(
            IWebHostEnvironment environment, 
            IUserRepository userRepo, 
            IAppLogger logger,
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager)
        {
            env = environment;
            this.userRepo = userRepo;
            this.logger = logger;
            this.userManager = userManager;
            this.signInManager = signInManager;
        }

        public override void OnActionExecuting(Microsoft.AspNetCore.Mvc.Filters.ActionExecutingContext context)
        {
            EnsureSessionPopulated();
            base.OnActionExecuting(context);
        }

        private void EnsureSessionPopulated()
        {
            if (User.Identity?.IsAuthenticated == true && HttpContext.Session.GetString("UserSession") == null)
            {
                HttpContext.Session.SetString("UserSession", User.Identity.Name ?? string.Empty);
                var userIdClaim = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier);
                if (userIdClaim != null && int.TryParse(userIdClaim.Value, out int uid))
                {
                    HttpContext.Session.SetInt32("UserId", uid);
                }
                
                string sessionRole = "2"; // Default to User (2)
                if (User.IsInRole("Admin")) sessionRole = "1";
                else if (User.IsInRole("SuperAdmin")) sessionRole = "3";
                HttpContext.Session.SetString("UserRole", sessionRole);
            }
        }

        private bool IsAdmin()
        {
            return User.IsInRole("Admin") || User.IsInRole("SuperAdmin");
        }

        // ---------------- DASHBOARD ----------------
        public IActionResult Dashboard()
        {
            if (HttpContext.Session.GetString("UserSession") == null)
            {
                logger.LogWarning("Dashboard", "Access Dashboard", "Unauthorized access attempt to dashboard: session was null.");
                return RedirectToAction("Login", "Account");
            }

            int userId = HttpContext.Session.GetInt32("UserId") ?? 0;
            ViewBag.Username = HttpContext.Session.GetString("UserSession");

            string roleId = HttpContext.Session.GetString("UserRole") ?? "";

            if (roleId == "1" || roleId == "3")
            {
                logger.LogInfo("Dashboard", "Access Dashboard", $"Admin dashboard accessed by user: {ViewBag.Username}");
                return View("AdminDashboard");
            }

            // Fetch user documents
            var docs = userRepo.GetUserDocuments(userId);
            
            var aadhaarDoc = docs.FirstOrDefault(d => d.DocumentType == "Aadhaar");
            var panDoc = docs.FirstOrDefault(d => d.DocumentType == "PAN");
            var otherDoc = docs.FirstOrDefault(d => d.DocumentType == "Other");

            ViewBag.AadhaarStatus = aadhaarDoc?.Status ?? "Missing";
            ViewBag.AadhaarName = aadhaarDoc?.FileName;
            ViewBag.AadhaarId = aadhaarDoc?.DocumentId ?? 0;

            ViewBag.PanStatus = panDoc?.Status ?? "Missing";
            ViewBag.PanName = panDoc?.FileName;
            ViewBag.PanId = panDoc?.DocumentId ?? 0;

            ViewBag.OtherStatus = otherDoc?.Status ?? "Missing";
            ViewBag.OtherName = otherDoc?.FileName;
            ViewBag.OtherId = otherDoc?.DocumentId ?? 0;

            ViewBag.HasMandatory = (aadhaarDoc != null && panDoc != null);
            ViewBag.HasAnyDocument = docs.Any();

            logger.LogInfo("Dashboard", "Access Dashboard", $"User dashboard accessed by user: {ViewBag.Username}");
            return View("UserDashboard");
        }

        // ---------------- USER LIST ---------------- 
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public IActionResult UserList()
        {
            if (HttpContext.Session.GetString("UserSession") == null)
            {
                logger.LogWarning("User Management", "Access User List", "Unauthorized access attempt to user list: session was null.");
                return RedirectToAction("Login", "Account");
            }

            try
            {
                using var con = db.GetConnection();

                string query = @"
                    SELECT
                        u.UserId,
                        u.FullName,
                        u.Username,
                        u.EmailId,
                        u.MobileNo,
                        r.RoleName
                    FROM UserMaster u
                    INNER JOIN RoleMaster r
                        ON u.RoleId = r.RoleId
                    ORDER BY u.UserId DESC";

                var users = con.Query<UserModel>(query).ToList();
                logger.LogInfo("User Management", "Access User List", "User list retrieved and viewed successfully.");
                return View(users);
            }
            catch (Exception ex)
            {
                logger.LogError("User Management", "Access User List", "Failed to retrieve user list from database.", ex);
                throw;
            }
        }

        // ---------------- USER DETAILS ----------------
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public IActionResult UserDetails(int id)
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("User Management", "Access User Details", $"Unauthorized attempt by non-admin to view details of User ID: {id}");
                return RedirectToAction("Dashboard");
            }

            try
            {
                using var con = db.GetConnection();

                string query = @"
                    SELECT
                        u.UserId,
                        u.FullName,
                        u.Username,
                        u.EmailId,
                        u.MobileNo,
                        u.CreatedDate,
                        r.RoleName
                    FROM UserMaster u
                    INNER JOIN RoleMaster r ON u.RoleId = r.RoleId
                    WHERE u.UserId = @UserId";

                var user = con.QueryFirstOrDefault<UserModel>(query, new { UserId = id });

                if (user == null)
                {
                    logger.LogWarning("User Management", "Access User Details", $"Admin attempted to view non-existent User ID: {id}");
                    return NotFound();
                }

                // Fetch user documents
                var docs = userRepo.GetUserDocuments(id);

                ViewBag.AadhaarDoc = docs.FirstOrDefault(d => d.DocumentType == "Aadhaar");
                ViewBag.PanDoc = docs.FirstOrDefault(d => d.DocumentType == "PAN");
                ViewBag.OtherDoc = docs.FirstOrDefault(d => d.DocumentType == "Other");

                logger.LogInfo("User Management", "Access User Details", $"Admin viewed user details for username: {user.Username} (ID: {id})");
                return View(user);
            }
            catch (Exception ex)
            {
                logger.LogError("User Management", "Access User Details", $"Failed to load user details for User ID: {id}", ex);
                throw;
            }
        }

        // ---------------- EDIT USER ----------------
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public IActionResult EditUser(int id)
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("User Management", "Edit User Form", $"Unauthorized attempt by non-admin to edit User ID: {id}");
                return RedirectToAction("Dashboard");
            }

            UserModel user = new();

            try
            {
                using var con = db.GetConnection();

                string query = @"
                    SELECT
                        UserId,
                        FullName,
                        Username,
                        EmailId,
                        MobileNo,
                        RoleId
                    FROM UserMaster
                    WHERE UserId = @UserId";

                user = con.QueryFirstOrDefault<UserModel>(query, new { UserId = id });

                if (user == null)
                {
                    logger.LogWarning("User Management", "Edit User Form", $"Admin attempted to edit non-existent User ID: {id}");
                    return NotFound();
                }

                logger.LogInfo("User Management", "Edit User Form", $"Admin loaded edit form for User ID: {id}, username: {user.Username}");
                return View(user);
            }
            catch (Exception ex)
            {
                logger.LogError("User Management", "Edit User Form", $"Failed to load edit form for User ID: {id}", ex);
                throw;
            }
        }

        [HttpPost]
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public IActionResult EditUser(UserModel user)
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("User Management", "Edit User Save", $"Unauthorized attempt by non-admin to save changes for User ID: {user.UserId}");
                return RedirectToAction("Dashboard");
            }

            try
            {
                userRepo.EditUser(user);
                TempData["Success"] = "User updated successfully.";
                logger.LogInfo("User Management", "Edit User Save", $"User details saved successfully by Admin for User ID: {user.UserId}, Username: {user.Username}");
            }
            catch (Exception ex)
            {
                TempData["Error"] = ex.Message;
                logger.LogError("User Management", "Edit User Save", $"Admin failed to save changes for User ID: {user.UserId}", ex);
            }

            return RedirectToAction("UserList");
        }

        // ---------------- DELETE USER ----------------
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public IActionResult DeleteUser(int id)
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("User Management", "Delete User", $"Unauthorized attempt by non-admin to delete User ID: {id}");
                return RedirectToAction("Dashboard");
            }

            try
            {
                if (userRepo.IsLastAdmin(id))
                {
                    TempData["Error"] = "Cannot delete last admin.";
                    logger.LogWarning("User Management", "Delete User", $"Delete operation blocked: User ID {id} is the last Admin in the system.");
                    return RedirectToAction("UserList");
                }

                userRepo.DeleteUser(id);
                TempData["Success"] = "User deleted successfully.";
                logger.LogInfo("User Management", "Delete User", $"User ID {id} deleted successfully by Admin.");
            }
            catch (Exception ex)
            {
                TempData["Error"] = ex.Message;
                logger.LogError("User Management", "Delete User", $"Failed to delete User ID {id}", ex);
            }

            return RedirectToAction("UserList");
        }

        // ---------------- UPLOAD DOCUMENTS (GET) ----------------
        public IActionResult UploadDocuments()
        {
            if (HttpContext.Session.GetString("UserSession") == null)
            {
                logger.LogWarning("Document Management", "Access Upload Page", "Unauthorized access attempt to upload page: session was null.");
                return RedirectToAction("Login", "Account");
            }

            int userId = HttpContext.Session.GetInt32("UserId") ?? 0;
            var docs = userRepo.GetUserDocuments(userId);

            ViewBag.AadhaarUploaded = docs.Any(d => d.DocumentType == "Aadhaar");
            ViewBag.PanUploaded = docs.Any(d => d.DocumentType == "PAN");
            ViewBag.OtherUploaded = docs.Any(d => d.DocumentType == "Other");

            ViewBag.Username = HttpContext.Session.GetString("UserSession");
            logger.LogInfo("Document Management", "Access Upload Page", "Document upload page loaded.");
            return View();
        }

        // ---------------- UPLOAD DOCUMENTS (POST) ----------------
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult UploadDocuments(IFormFile? aadhaarFile, IFormFile? panFile, IFormFile? otherFile)
        {
            if (HttpContext.Session.GetString("UserSession") == null)
            {
                logger.LogWarning("Document Management", "Upload Documents Save", "Unauthorized upload attempt: session was null.");
                return RedirectToAction("Login", "Account");
            }

            int userId = HttpContext.Session.GetInt32("UserId") ?? 0;
            if (userId == 0)
            {
                logger.LogWarning("Document Management", "Upload Documents Save", "Unauthorized upload attempt: invalid user ID.");
                return RedirectToAction("Login", "Account");
            }

            var docs = userRepo.GetUserDocuments(userId);
            bool hasAadhaar = docs.Any(d => d.DocumentType == "Aadhaar");
            bool hasPan = docs.Any(d => d.DocumentType == "PAN");

            // Server-side validation of requirements
            if (!hasAadhaar && aadhaarFile == null)
            {
                TempData["Error"] = "Aadhaar Card is mandatory and must be uploaded.";
                logger.LogWarning("Document Management", "Upload Documents Save", "Validation failed: Aadhaar Card is missing and mandatory.");
                return RedirectToAction("UploadDocuments");
            }
            if (!hasPan && panFile == null)
            {
                TempData["Error"] = "PAN Card is mandatory and must be uploaded.";
                logger.LogWarning("Document Management", "Upload Documents Save", "Validation failed: PAN Card is missing and mandatory.");
                return RedirectToAction("UploadDocuments");
            }

            try
            {
                string uploadFolder = Path.Combine(env.WebRootPath, "uploads");
                if (!Directory.Exists(uploadFolder))
                    Directory.CreateDirectory(uploadFolder);

                // Helper to validate and save
                void ValidateAndSave(IFormFile file, string docType)
                {
                    if (file == null || file.Length == 0) return;

                    // 1. Extension check
                    string ext = Path.GetExtension(file.FileName).ToLower();
                    if (ext != ".pdf")
                    {
                        logger.LogWarning("Document Management", "File Validation", $"File validation failure: {docType} file '{file.FileName}' is not a .pdf extension.");
                        throw new Exception($"Only PDF files are allowed for {docType}.");
                    }

                    // 2. MIME type check
                    if (file.ContentType.ToLower() != "application/pdf")
                    {
                        logger.LogWarning("Document Management", "File Validation", $"File validation failure: {docType} file '{file.FileName}' has invalid MIME type '{file.ContentType}'.");
                        throw new Exception($"Only PDF files (MIME type application/pdf) are allowed for {docType}.");
                    }

                    // 3. File size check (2 MB)
                    if (file.Length > 2 * 1024 * 1024)
                    {
                        logger.LogWarning("Document Management", "File Validation", $"File size validation failure: {docType} file '{file.FileName}' exceeds 2 MB (Size: {file.Length} bytes).");
                        throw new Exception($"File size for {docType} exceeds the maximum limit of 2 MB.");
                    }

                    // 4. Magic bytes check
                    using (var stream = file.OpenReadStream())
                    {
                        if (!IsGenuinePdf(stream))
                        {
                            logger.LogSecurity("Document Management", "File Validation", $"Security alert: Genuine PDF signature check failed for {docType} file '{file.FileName}'. Magic bytes mismatch.");
                            throw new Exception($"The uploaded file for {docType} is not a genuine PDF document.");
                        }
                    }

                    logger.LogInfo("Document Management", "File Validation", $"File validation check successful for {docType} file '{file.FileName}'.");

                    // Save file
                    string fileName = Guid.NewGuid() + ".pdf";
                    using (var stream = new FileStream(Path.Combine(uploadFolder, fileName), FileMode.Create))
                    {
                        file.CopyTo(stream);
                    }

                    userRepo.SaveDocuments(new UserDocumentModel
                    {
                        UserId = userId,
                        DocumentType = docType,
                        FileName = file.FileName,
                        FilePath = fileName
                    });
                    logger.LogInfo("Document Management", "Upload Documents Save", $"Document '{file.FileName}' ({docType}) uploaded and saved successfully.");
                }

                if (aadhaarFile != null) ValidateAndSave(aadhaarFile, "Aadhaar");
                if (panFile != null) ValidateAndSave(panFile, "PAN");
                if (otherFile != null) ValidateAndSave(otherFile, "Other");

                TempData["Success"] = "Documents uploaded successfully.";
            }
            catch (Exception ex)
            {
                TempData["Error"] = "Upload failed: " + ex.Message;
                logger.LogError("Document Management", "Upload Documents Save", "Document upload operation encountered an error.", ex);
                return RedirectToAction("UploadDocuments");
            }

            return RedirectToAction("Dashboard");
        }

        // ---------------- VIEW USER DOCUMENTS ----------------
        public IActionResult ViewDocuments()
        {
            int userId = HttpContext.Session.GetInt32("UserId") ?? 0;
            if (userId == 0)
            {
                logger.LogWarning("Document Management", "View Documents", "Unauthorized access attempt to view documents: session was null.");
                return RedirectToAction("Login", "Account");
            }

            var docs = userRepo.GetUserDocuments(userId);

            if (docs == null || !docs.Any())
            {
                TempData["Error"] = "You have not uploaded any documents yet.";
                logger.LogInfo("Document Management", "View Documents", "User viewed documents page but has no uploads.");
                return RedirectToAction("Dashboard");
            }

            var docSizes = new Dictionary<int, string>();
            foreach (var doc in docs)
            {
                string physicalPath = Path.Combine(env.WebRootPath, "uploads", doc.FilePath ?? "");
                if (System.IO.File.Exists(physicalPath))
                {
                    var fileInfo = new FileInfo(physicalPath);
                    double sizeInMb = (double)fileInfo.Length / (1024 * 1024);
                    docSizes[doc.DocumentId] = sizeInMb.ToString("0.00") + " MB";
                }
                else
                {
                    docSizes[doc.DocumentId] = "Unknown";
                }
            }
            ViewBag.DocSizes = docSizes;
            ViewBag.Username = HttpContext.Session.GetString("UserSession");

            logger.LogInfo("Document Management", "View Documents", "User viewed uploaded documents list.");
            return View(docs);
        }

        // ---------------- REPLACE DOCUMENT ----------------
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult ReplaceDocument(int documentId, IFormFile pdfFile)
        {
            if (HttpContext.Session.GetString("UserSession") == null)
            {
                logger.LogWarning("Document Management", "Replace Document", "Unauthorized replace attempt: session was null.");
                return RedirectToAction("Login", "Account");
            }

            if (pdfFile == null || pdfFile.Length == 0)
            {
                TempData["Error"] = "Please select a valid PDF file to replace.";
                logger.LogWarning("Document Management", "Replace Document", "Replacement failed: selected file was null or empty.");
                return RedirectToAction("ViewDocuments");
            }

            // Server-side Validation
            // 1. File Extension check
            string ext = Path.GetExtension(pdfFile.FileName).ToLower();
            if (ext != ".pdf")
            {
                TempData["Error"] = "Server-side Validation Error: Only PDF files are allowed.";
                logger.LogWarning("Document Management", "File Validation", $"File validation failure on replace: '{pdfFile.FileName}' is not a .pdf extension.");
                return RedirectToAction("ViewDocuments");
            }

            // 2. MIME type check
            if (pdfFile.ContentType.ToLower() != "application/pdf")
            {
                TempData["Error"] = "Server-side Validation Error: Only PDF files (MIME type application/pdf) are allowed.";
                logger.LogWarning("Document Management", "File Validation", $"File validation failure on replace: '{pdfFile.FileName}' has invalid MIME type '{pdfFile.ContentType}'.");
                return RedirectToAction("ViewDocuments");
            }

            // 3. File size check (2 MB)
            if (pdfFile.Length > 2 * 1024 * 1024)
            {
                TempData["Error"] = "Server-side Validation Error: File size exceeds the maximum limit of 2 MB.";
                logger.LogWarning("Document Management", "File Validation", $"File size validation failure on replace: '{pdfFile.FileName}' exceeds 2 MB (Size: {pdfFile.Length} bytes).");
                return RedirectToAction("ViewDocuments");
            }

            // 4. Magic bytes check
            using (var stream = pdfFile.OpenReadStream())
            {
                if (!IsGenuinePdf(stream))
                {
                    TempData["Error"] = "Server-side Validation Error: The uploaded file is not a genuine PDF document. File signature check failed.";
                    logger.LogSecurity("Document Management", "File Validation", $"Security alert: Genuine PDF signature check failed on replace for file '{pdfFile.FileName}'. Magic bytes mismatch.");
                    return RedirectToAction("ViewDocuments");
                }
            }

            logger.LogInfo("Document Management", "File Validation", $"File validation check successful on replace for file '{pdfFile.FileName}'.");

            try
            {
                using var con = db.GetConnection();
                // Get old file info to delete it from disk
                string query = "SELECT FilePath FROM UserDocuments WHERE DocumentId = @DocumentId;";
                string oldFilePath = con.ExecuteScalar<string>(query, new { DocumentId = documentId });

                string uploadFolder = Path.Combine(env.WebRootPath, "uploads");
                string newFileName = Guid.NewGuid() + ".pdf";

                // Save new file to uploads
                using (var stream = new FileStream(Path.Combine(uploadFolder, newFileName), FileMode.Create))
                {
                    pdfFile.CopyTo(stream);
                }

                // Update database
                userRepo.ReplaceDocument(documentId, pdfFile.FileName, newFileName);

                // Delete old file if exists
                if (!string.IsNullOrEmpty(oldFilePath))
                {
                    string oldPhysicalPath = Path.Combine(uploadFolder, oldFilePath);
                    if (System.IO.File.Exists(oldPhysicalPath))
                    {
                        System.IO.File.Delete(oldPhysicalPath);
                    }
                }

                TempData["Success"] = "Document replaced successfully.";
                logger.LogInfo("Document Management", "Replace Document", $"Document ID {documentId} replaced successfully with file '{pdfFile.FileName}'.");
            }
            catch (Exception ex)
            {
                TempData["Error"] = "Replacement failed: " + ex.Message;
                logger.LogError("Document Management", "Replace Document", $"Failed to replace Document ID: {documentId}", ex);
            }

            return RedirectToAction("ViewDocuments");
        }

        // ---------------- DELETE DOCUMENT ----------------
        [HttpPost]
        [ValidateAntiForgeryToken]
        public IActionResult DeleteDocument(int documentId)
        {
            if (HttpContext.Session.GetString("UserSession") == null)
            {
                logger.LogWarning("Document Management", "Delete Document", "Unauthorized delete attempt: session was null.");
                return RedirectToAction("Login", "Account");
            }

            try
            {
                using var con = db.GetConnection();
                // Get file info to delete from disk
                string query = "SELECT FilePath FROM UserDocuments WHERE DocumentId = @DocumentId;";
                string filePath = con.ExecuteScalar<string>(query, new { DocumentId = documentId });

                // Delete from DB
                userRepo.DeleteDocument(documentId);

                // Delete from disk
                if (!string.IsNullOrEmpty(filePath))
                {
                    string physicalPath = Path.Combine(env.WebRootPath, "uploads", filePath);
                    if (System.IO.File.Exists(physicalPath))
                    {
                        System.IO.File.Delete(physicalPath);
                    }
                }

                TempData["Success"] = "Document deleted successfully.";
                logger.LogInfo("Document Management", "Delete Document", $"Document ID {documentId} deleted successfully.");
            }
            catch (Exception ex)
            {
                TempData["Error"] = "Deletion failed: " + ex.Message;
                logger.LogError("Document Management", "Delete Document", $"Failed to delete Document ID: {documentId}", ex);
            }

            return RedirectToAction("ViewDocuments");
        }

        // ---------------- ADMIN DOCUMENTS ----------------
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public IActionResult AdminDocuments()
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("Document Verification", "Access Admin Documents", "Unauthorized attempt to view admin documents verification list.");
                return RedirectToAction("Dashboard");
            }

            var docs = userRepo.GetAllDocuments();
            logger.LogInfo("Document Verification", "Access Admin Documents", "Admin documents verification list viewed.");
            return View(docs);
        }

        // ---------------- APPROVE ----------------
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public IActionResult ApproveDocument(int documentId)
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("Document Verification", "Approve Document", $"Unauthorized attempt by non-admin to approve Document ID: {documentId}");
                return RedirectToAction("Dashboard");
            }

            try
            {
                int adminId = HttpContext.Session.GetInt32("UserId") ?? 0;
                userRepo.ApproveDocument(documentId, adminId);
                TempData["Success"] = "Document approved successfully.";
                logger.LogInfo("Document Verification", "Approve Document", $"Document ID {documentId} approved successfully by Admin ID {adminId}.");
            }
            catch (Exception ex)
            {
                TempData["Error"] = "Error approving document: " + ex.Message;
                logger.LogError("Document Verification", "Approve Document", $"Error approving Document ID: {documentId}", ex);
            }

            return RedirectToAction("AdminDocuments");
        }

        // ---------------- REJECT ----------------
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public IActionResult RejectDocument(int documentId)
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("Document Verification", "Reject Document", $"Unauthorized attempt by non-admin to reject Document ID: {documentId}");
                return RedirectToAction("Dashboard");
            }

            try
            {
                int adminId = HttpContext.Session.GetInt32("UserId") ?? 0;
                userRepo.RejectDocument(documentId, adminId);
                TempData["Success"] = "Document rejected successfully.";
                logger.LogInfo("Document Verification", "Reject Document", $"Document ID {documentId} rejected successfully by Admin ID {adminId}.");
            }
            catch (Exception ex)
            {
                TempData["Error"] = "Error rejecting document: " + ex.Message;
                logger.LogError("Document Verification", "Reject Document", $"Error rejecting Document ID: {documentId}", ex);
            }

            return RedirectToAction("AdminDocuments");
        }

        private static bool IsGenuinePdf(Stream stream)
        {
            try
            {
                byte[] buffer = new byte[4];
                stream.Position = 0;
                int read = stream.Read(buffer, 0, 4);
                stream.Position = 0; // reset
                if (read < 4) return false;
                
                // %PDF signature: 0x25 0x50 0x44 0x46
                return buffer[0] == 0x25 && buffer[1] == 0x50 && buffer[2] == 0x44 && buffer[3] == 0x46;
            }
            catch
            {
                return false;
            }
        }

        // ---------------- ERROR HANDLING ----------------

        [AllowAnonymous]
        public IActionResult Error(string? correlationId)
        {
            ViewBag.CorrelationId = correlationId ?? HttpContext.TraceIdentifier;
            return View();
        }

        [AllowAnonymous]
        public IActionResult StatusCodeHandler(int code)
        {
            ViewBag.StatusCode = code;
            string message = "Something went wrong.";
            string description = "An unexpected error occurred.";

            switch (code)
            {
                case 400:
                    message = "Bad Request";
                    description = "The server cannot process your request due to invalid syntax.";
                    break;
                case 401:
                    message = "Unauthorized Access";
                    description = "You must log in to access this resource.";
                    break;
                case 403:
                    message = "Access Forbidden";
                    description = "You do not have permission to view this resource.";
                    break;
                case 404:
                    message = "Page Not Found";
                    description = "The page you are looking for does not exist or has been moved.";
                    break;
                case 500:
                    message = "Internal Server Error";
                    description = "An unexpected error occurred on our servers. We have logged the details.";
                    break;
            }

            ViewBag.Message = message;
            ViewBag.Description = description;
            return View("StatusCode");
        }

        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public async Task<IActionResult> ErrorLogs(
            string? search, 
            string? severity, 
            string? exceptionType, 
            string? dateRange,
            string? startDate,
            string? endDate,
            string? resolutionStatus,
            string? sortOrder,
            int pageNumber = 1, 
            int pageSize = 10)
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("Error Logging", "Access Error Logs", "Unauthorized attempt by non-admin to view error logs.");
                return RedirectToAction("Dashboard");
            }

            try
            {
                using var con = db.GetConnection();
                con.Open();

                // 1. Get distinct filter options
                var distinctExceptionTypes = (await con.QueryAsync<string>("SELECT DISTINCT exception_type FROM errorlogs WHERE exception_type IS NOT NULL ORDER BY exception_type;")).ToList();
                var distinctSeverities = (await con.QueryAsync<string>("SELECT DISTINCT severity FROM errorlogs WHERE severity IS NOT NULL ORDER BY severity;")).ToList();

                // 2. Build where clause
                string whereClause = "WHERE 1=1";
                var parameters = new DynamicParameters();

                if (!string.IsNullOrEmpty(search))
                {
                    whereClause += " AND (exception_message ILIKE @Search OR controller ILIKE @Search OR action ILIKE @Search OR username ILIKE @Search OR correlation_id ILIKE @Search)";
                    parameters.Add("Search", $"%{search}%");
                }

                if (!string.IsNullOrEmpty(severity))
                {
                    whereClause += " AND severity = @Severity";
                    parameters.Add("Severity", severity);
                }

                if (!string.IsNullOrEmpty(exceptionType))
                {
                    whereClause += " AND exception_type = @ExceptionType";
                    parameters.Add("ExceptionType", exceptionType);
                }

                if (!string.IsNullOrEmpty(resolutionStatus) && resolutionStatus != "All")
                {
                    if (resolutionStatus.Equals("Resolved", StringComparison.OrdinalIgnoreCase))
                    {
                        whereClause += " AND is_resolved = TRUE";
                    }
                    else if (resolutionStatus.Equals("Unresolved", StringComparison.OrdinalIgnoreCase))
                    {
                        whereClause += " AND is_resolved = FALSE";
                    }
                }

                if (!string.IsNullOrEmpty(dateRange))
                {
                    DateTime today = DateTime.Today;
                    switch (dateRange.ToLower())
                    {
                        case "today":
                            whereClause += " AND date_time >= @StartRange";
                            parameters.Add("StartRange", today);
                            break;
                        case "yesterday":
                            whereClause += " AND date_time >= @StartRange AND date_time < @EndRange";
                            parameters.Add("StartRange", today.AddDays(-1));
                            parameters.Add("EndRange", today);
                            break;
                        case "last7days":
                            whereClause += " AND date_time >= @StartRange";
                            parameters.Add("StartRange", today.AddDays(-7));
                            break;
                        case "last30days":
                            whereClause += " AND date_time >= @StartRange";
                            parameters.Add("StartRange", today.AddDays(-30));
                            break;
                        case "custom":
                            if (DateTime.TryParse(startDate, out DateTime sDate))
                            {
                                whereClause += " AND date_time >= @CustomStart";
                                parameters.Add("CustomStart", sDate.Date);
                            }
                            if (DateTime.TryParse(endDate, out DateTime eDate))
                            {
                                whereClause += " AND date_time <= @CustomEnd";
                                parameters.Add("CustomEnd", eDate.Date.AddDays(1).AddTicks(-1));
                            }
                            break;
                    }
                }

                // 3. Get total item count
                string countSql = $"SELECT COUNT(1) FROM errorlogs {whereClause}";
                int totalItems = await con.ExecuteScalarAsync<int>(countSql, parameters);

                // 4. Determine Sort Order
                string orderBy = "ORDER BY logid DESC"; // Default
                if (!string.IsNullOrEmpty(sortOrder))
                {
                    switch (sortOrder.ToLower())
                    {
                        case "date_asc": orderBy = "ORDER BY date_time ASC"; break;
                        case "date_desc": orderBy = "ORDER BY date_time DESC"; break;
                        case "msg_asc": orderBy = "ORDER BY exception_message ASC"; break;
                        case "msg_desc": orderBy = "ORDER BY exception_message DESC"; break;
                        case "severity_asc": orderBy = "ORDER BY severity ASC"; break;
                        case "severity_desc": orderBy = "ORDER BY severity DESC"; break;
                    }
                }

                // 5. Query page of logs
                int offset = (pageNumber - 1) * pageSize;
                string querySql = $@"
                    SELECT 
                        logid AS LogId, 
                        date_time AS DateTime, 
                        last_occurred_on AS LastOccurredOn,
                        occurrence_count AS OccurrenceCount,
                        username AS Username, 
                        userid AS UserId, 
                        role AS Role, 
                        controller AS Controller, 
                        action AS Action, 
                        request_url AS RequestUrl, 
                        http_method AS HttpMethod, 
                        ip_address AS IpAddress, 
                        user_agent AS UserAgent, 
                        exception_type AS ExceptionType, 
                        exception_message AS ExceptionMessage, 
                        inner_exception AS InnerException, 
                        stack_trace AS StackTrace, 
                        status_code AS StatusCode, 
                        severity AS Severity, 
                        correlation_id AS CorrelationId,
                        is_resolved AS IsResolved,
                        resolved_by AS ResolvedBy,
                        resolved_on AS ResolvedOn,
                        remarks AS Remarks
                    FROM errorlogs
                    {whereClause}
                    {orderBy}
                    LIMIT @PageSize OFFSET @Offset;";
                
                parameters.Add("PageSize", pageSize);
                parameters.Add("Offset", offset);

                var logs = (await con.QueryAsync<ErrorLogViewModel>(querySql, parameters)).ToList();

                // 6. Fetch stats
                int totalErrorsCount = await con.ExecuteScalarAsync<int>("SELECT COUNT(1) FROM errorlogs;");
                int todaysErrorsCount = await con.ExecuteScalarAsync<int>("SELECT COALESCE(SUM(occurrence_count), 0) FROM errorlogs WHERE date_time >= @Today;", new { Today = DateTime.Today });
                int criticalErrorsCount = await con.ExecuteScalarAsync<int>("SELECT COUNT(1) FROM errorlogs WHERE severity = 'Critical' AND is_resolved = FALSE;");
                int resolvedErrorsCount = await con.ExecuteScalarAsync<int>("SELECT COUNT(1) FROM errorlogs WHERE is_resolved = TRUE;");

                var model = new ErrorLogsListViewModel
                {
                    Logs = logs,
                    TotalItems = totalItems,
                    PageNumber = pageNumber,
                    PageSize = pageSize,
                    Search = search,
                    Severity = severity,
                    ExceptionType = exceptionType,
                    DateRange = dateRange,
                    StartDate = startDate,
                    EndDate = endDate,
                    ResolutionStatus = resolutionStatus,
                    SortOrder = sortOrder,
                    ExceptionTypes = distinctExceptionTypes,
                    Severities = distinctSeverities,
                    TotalErrorsCount = totalErrorsCount,
                    TodaysErrorsCount = todaysErrorsCount,
                    CriticalErrorsCount = criticalErrorsCount,
                    ResolvedErrorsCount = resolvedErrorsCount
                };

                logger.LogInfo("Error Logging", "View Error Logs", $"Retrieved error logs page {pageNumber}. Total count: {totalItems}");
                return View(model);
            }
            catch (Exception ex)
            {
                logger.LogError("Error Logging", "View Error Logs", "Failed to retrieve error logs list from database.", ex);
                throw;
            }
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public async Task<IActionResult> ResolveErrorLog(int id, string? remarks)
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("Error Logging", "Resolve Error Log", $"Unauthorized attempt to resolve error log ID {id}.");
                return RedirectToAction("Dashboard");
            }

            try
            {
                string resolver = User.Identity?.Name ?? "Admin";
                using var con = db.GetConnection();
                con.Open();

                string sql = @"
                    UPDATE errorlogs 
                    SET is_resolved = TRUE, 
                        resolved_by = @ResolvedBy, 
                        resolved_on = @ResolvedOn, 
                        remarks = @Remarks 
                    WHERE logid = @Id;";

                await con.ExecuteAsync(sql, new
                {
                    ResolvedBy = resolver,
                    ResolvedOn = DateTime.Now,
                    Remarks = remarks ?? "Resolved by Administrator.",
                    Id = id
                });

                logger.LogInfo("Error Logging", "Resolve Error Log", $"Error log ID {id} was marked as resolved by {resolver}.");
                TempData["Success"] = "Error log resolved successfully.";
            }
            catch (Exception ex)
            {
                logger.LogError("Error Logging", "Resolve Error Log", $"Failed to resolve error log ID {id}.", ex);
                TempData["Error"] = "Failed to resolve error log.";
            }

            return RedirectToAction("ErrorLogs");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public async Task<IActionResult> DeleteErrorLog(int id)
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("Error Logging", "Delete Error Log", $"Unauthorized attempt to delete error log ID {id}.");
                return RedirectToAction("Dashboard");
            }

            try
            {
                using var con = db.GetConnection();
                con.Open();
                await con.ExecuteAsync("DELETE FROM errorlogs WHERE logid = @Id;", new { Id = id });
                logger.LogInfo("Error Logging", "Delete Error Log", $"Error log ID {id} was deleted successfully.");
                TempData["Success"] = "Error log deleted successfully.";
            }
            catch (Exception ex)
            {
                logger.LogError("Error Logging", "Delete Error Log", $"Failed to delete error log ID {id}.", ex);
                TempData["Error"] = "Failed to delete error log.";
            }

            return RedirectToAction("ErrorLogs");
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        [Authorize(Policy = "RequireSuperAdmin")]
        public async Task<IActionResult> ClearAllErrorLogs()
        {
            if (!User.IsInRole("SuperAdmin"))
            {
                logger.LogSecurity("Error Logging", "Clear All Error Logs", "Unauthorized attempt to clear all error logs.");
                return RedirectToAction("Dashboard");
            }

            try
            {
                using var con = db.GetConnection();
                con.Open();
                await con.ExecuteAsync("TRUNCATE TABLE errorlogs;");
                logger.LogInfo("Error Logging", "Clear All Error Logs", "All error logs cleared successfully.");
                TempData["Success"] = "All error logs cleared successfully.";
            }
            catch (Exception ex)
            {
                logger.LogError("Error Logging", "Clear All Error Logs", "Failed to clear all error logs.", ex);
                TempData["Error"] = "Failed to clear all error logs.";
            }

            return RedirectToAction("ErrorLogs");
        }

        [Authorize(Policy = "RequireAdminOrSuperAdmin")]
        public async Task<IActionResult> ExportErrorLogs(
            string? search,
            string? severity,
            string? exceptionType,
            string? dateRange,
            string? startDate,
            string? endDate,
            string? resolutionStatus,
            string? sortOrder,
            string format = "csv")
        {
            if (!IsAdmin())
            {
                logger.LogSecurity("Error Logging", "Export Error Logs", "Unauthorized attempt to export error logs.");
                return RedirectToAction("Dashboard");
            }

            try
            {
                using var con = db.GetConnection();
                con.Open();

                string whereClause = "WHERE 1=1";
                var parameters = new DynamicParameters();

                if (!string.IsNullOrEmpty(search))
                {
                    whereClause += " AND (exception_message ILIKE @Search OR controller ILIKE @Search OR action ILIKE @Search OR username ILIKE @Search OR correlation_id ILIKE @Search)";
                    parameters.Add("Search", $"%{search}%");
                }

                if (!string.IsNullOrEmpty(severity))
                {
                    whereClause += " AND severity = @Severity";
                    parameters.Add("Severity", severity);
                }

                if (!string.IsNullOrEmpty(exceptionType))
                {
                    whereClause += " AND exception_type = @ExceptionType";
                    parameters.Add("ExceptionType", exceptionType);
                }

                if (!string.IsNullOrEmpty(resolutionStatus) && resolutionStatus != "All")
                {
                    if (resolutionStatus.Equals("Resolved", StringComparison.OrdinalIgnoreCase))
                    {
                        whereClause += " AND is_resolved = TRUE";
                    }
                    else if (resolutionStatus.Equals("Unresolved", StringComparison.OrdinalIgnoreCase))
                    {
                        whereClause += " AND is_resolved = FALSE";
                    }
                }

                if (!string.IsNullOrEmpty(dateRange))
                {
                    DateTime today = DateTime.Today;
                    switch (dateRange.ToLower())
                    {
                        case "today":
                            whereClause += " AND date_time >= @StartRange";
                            parameters.Add("StartRange", today);
                            break;
                        case "yesterday":
                            whereClause += " AND date_time >= @StartRange AND date_time < @EndRange";
                            parameters.Add("StartRange", today.AddDays(-1));
                            parameters.Add("EndRange", today);
                            break;
                        case "last7days":
                            whereClause += " AND date_time >= @StartRange";
                            parameters.Add("StartRange", today.AddDays(-7));
                            break;
                        case "last30days":
                            whereClause += " AND date_time >= @StartRange";
                            parameters.Add("StartRange", today.AddDays(-30));
                            break;
                        case "custom":
                            if (DateTime.TryParse(startDate, out DateTime sDate))
                            {
                                whereClause += " AND date_time >= @CustomStart";
                                parameters.Add("CustomStart", sDate.Date);
                            }
                            if (DateTime.TryParse(endDate, out DateTime eDate))
                            {
                                whereClause += " AND date_time <= @CustomEnd";
                                parameters.Add("CustomEnd", eDate.Date.AddDays(1).AddTicks(-1));
                            }
                            break;
                    }
                }

                string orderBy = "ORDER BY logid DESC";
                if (!string.IsNullOrEmpty(sortOrder))
                {
                    switch (sortOrder.ToLower())
                    {
                        case "date_asc": orderBy = "ORDER BY date_time ASC"; break;
                        case "date_desc": orderBy = "ORDER BY date_time DESC"; break;
                        case "msg_asc": orderBy = "ORDER BY exception_message ASC"; break;
                        case "msg_desc": orderBy = "ORDER BY exception_message DESC"; break;
                        case "severity_asc": orderBy = "ORDER BY severity ASC"; break;
                        case "severity_desc": orderBy = "ORDER BY severity DESC"; break;
                    }
                }

                string querySql = $@"
                    SELECT 
                        logid AS LogId, 
                        date_time AS DateTime, 
                        last_occurred_on AS LastOccurredOn,
                        occurrence_count AS OccurrenceCount,
                        username AS Username, 
                        userid AS UserId, 
                        role AS Role, 
                        controller AS Controller, 
                        action AS Action, 
                        request_url AS RequestUrl, 
                        http_method AS HttpMethod, 
                        ip_address AS IpAddress, 
                        user_agent AS UserAgent, 
                        exception_type AS ExceptionType, 
                        exception_message AS ExceptionMessage, 
                        inner_exception AS InnerException, 
                        stack_trace AS StackTrace, 
                        status_code AS StatusCode, 
                        severity AS Severity, 
                        correlation_id AS CorrelationId,
                        is_resolved AS IsResolved,
                        resolved_by AS ResolvedBy,
                        resolved_on AS ResolvedOn,
                        remarks AS Remarks
                    FROM errorlogs
                    {whereClause}
                    {orderBy};";

                var logs = (await con.QueryAsync<ErrorLogViewModel>(querySql, parameters)).ToList();

                var sb = new System.Text.StringBuilder();
                sb.AppendLine("Log ID,Date Time,Last Occurred On,Count,Username,User ID,Role,Controller,Action,Request URL,Method,IP Address,Exception Type,Message,Severity,Resolved,Resolved By,Resolved On,Remarks");

                foreach (var log in logs)
                {
                    sb.AppendLine($"\"{log.LogId}\",\"{log.DateTime:yyyy-MM-dd HH:mm:ss}\",\"{log.LastOccurredOn:yyyy-MM-dd HH:mm:ss}\",\"{log.OccurrenceCount}\",\"{EscapeCsv(log.Username)}\",\"{log.UserId}\",\"{EscapeCsv(log.Role)}\",\"{EscapeCsv(log.Controller)}\",\"{EscapeCsv(log.Action)}\",\"{EscapeCsv(log.RequestUrl)}\",\"{EscapeCsv(log.HttpMethod)}\",\"{EscapeCsv(log.IpAddress)}\",\"{EscapeCsv(log.ExceptionType)}\",\"{EscapeCsv(log.ExceptionMessage)}\",\"{EscapeCsv(log.Severity)}\",\"{log.IsResolved}\",\"{EscapeCsv(log.ResolvedBy)}\",\"{log.ResolvedOn:yyyy-MM-dd HH:mm:ss}\",\"{EscapeCsv(log.Remarks)}\"");
                }

                var csvBytes = System.Text.Encoding.UTF8.GetBytes(sb.ToString());
                var bom = new byte[] { 0xEF, 0xBB, 0xBF };
                var resultBytes = new byte[bom.Length + csvBytes.Length];
                Buffer.BlockCopy(bom, 0, resultBytes, 0, bom.Length);
                Buffer.BlockCopy(csvBytes, 0, resultBytes, bom.Length, csvBytes.Length);

                string fileExtension = format.ToLower() == "excel" ? "xls" : "csv";
                string contentType = format.ToLower() == "excel" ? "application/vnd.ms-excel" : "text/csv";
                string fileName = $"error_logs_{DateTime.Now:yyyyMMddHHmmss}.{fileExtension}";

                logger.LogInfo("Error Logging", "Export Error Logs", $"Exported {logs.Count} error logs successfully in {format} format.");
                return File(resultBytes, contentType, fileName);
            }
            catch (Exception ex)
            {
                logger.LogError("Error Logging", "Export Error Logs", "Failed to export error logs.", ex);
                throw;
            }
        }

        private string EscapeCsv(string? value)
        {
            if (value == null) return string.Empty;
            return value.Replace("\"", "\"\"");
        }

        // ---------------- LOGOUT ----------------
        public async Task<IActionResult> Logout()
        {
            string? username = User.Identity?.Name ?? HttpContext.Session.GetString("UserSession");
            await signInManager.SignOutAsync();
            HttpContext.Session.Clear();
            logger.LogInfo("Authentication", "User Logout", $"User {username ?? "Unknown"} logged out successfully.");
            return RedirectToAction("Login", "Account");
        }
    }
}