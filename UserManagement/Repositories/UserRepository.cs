using Dapper;
using Npgsql;
using System.Collections.Generic;
using System.Linq;
using UserManagement.Models;
using UserManagement.Services;

namespace UserManagement.Repositories
{
    public class UserRepository : IUserRepository
    {
        private readonly DBHelper db = new DBHelper();
        private readonly IAppLogger logger;

        public UserRepository(IAppLogger logger)
        {
            this.logger = logger;
            EnsureDatabaseSchema();
        }

        private void EnsureDatabaseSchema()
        {
            try
            {
                using var con = db.GetConnection();
                
                // Add identity columns to usermaster table
                con.Execute(@"
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS resettoken VARCHAR(255);
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS resettokenexpiry TIMESTAMP;
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS normalizedusername VARCHAR(256);
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS normalizedemail VARCHAR(256);
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS emailconfirmed BOOLEAN DEFAULT FALSE;
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS securitystamp VARCHAR;
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS concurrencystamp VARCHAR;
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS phonenumberconfirmed BOOLEAN DEFAULT FALSE;
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS twofactorenabled BOOLEAN DEFAULT FALSE;
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS lockoutend TIMESTAMP WITH TIME ZONE;
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS lockoutenabled BOOLEAN DEFAULT FALSE;
                    ALTER TABLE usermaster ADD COLUMN IF NOT EXISTS accessfailedcount INTEGER DEFAULT 0;
                ");

                // Add identity columns to rolemaster table
                con.Execute(@"
                    ALTER TABLE rolemaster ADD COLUMN IF NOT EXISTS normalizedname VARCHAR(256);
                    ALTER TABLE rolemaster ADD COLUMN IF NOT EXISTS concurrencystamp VARCHAR;
                ");

                // Create Identity link and claim tables
                con.Execute(@"
                    CREATE TABLE IF NOT EXISTS aspnetuserroles (
                        userid INTEGER NOT NULL,
                        roleid INTEGER NOT NULL,
                        CONSTRAINT pk_aspnetuserroles PRIMARY KEY (userid, roleid),
                        CONSTRAINT fk_aspnetuserroles_usermaster FOREIGN KEY (userid) REFERENCES usermaster(userid) ON DELETE CASCADE,
                        CONSTRAINT fk_aspnetuserroles_rolemaster FOREIGN KEY (roleid) REFERENCES rolemaster(roleid) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS aspnetuserclaims (
                        id SERIAL PRIMARY KEY,
                        userid INTEGER NOT NULL,
                        claimtype VARCHAR,
                        claimvalue VARCHAR,
                        CONSTRAINT fk_aspnetuserclaims_usermaster FOREIGN KEY (userid) REFERENCES usermaster(userid) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS aspnetuserlogins (
                        loginprovider VARCHAR(128) NOT NULL,
                        providerkey VARCHAR(128) NOT NULL,
                        providerdisplayname VARCHAR,
                        userid INTEGER NOT NULL,
                        CONSTRAINT pk_aspnetuserlogins PRIMARY KEY (loginprovider, providerkey),
                        CONSTRAINT fk_aspnetuserlogins_usermaster FOREIGN KEY (userid) REFERENCES usermaster(userid) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS aspnetusertokens (
                        userid INTEGER NOT NULL,
                        loginprovider VARCHAR(128) NOT NULL,
                        name VARCHAR(128) NOT NULL,
                        value VARCHAR,
                        CONSTRAINT pk_aspnetusertokens PRIMARY KEY (userid, loginprovider, name),
                        CONSTRAINT fk_aspnetusertokens_usermaster FOREIGN KEY (userid) REFERENCES usermaster(userid) ON DELETE CASCADE
                    );

                    CREATE TABLE IF NOT EXISTS aspnetroleclaims (
                        id SERIAL PRIMARY KEY,
                        roleid INTEGER NOT NULL,
                        claimtype VARCHAR,
                        claimvalue VARCHAR,
                        CONSTRAINT fk_aspnetroleclaims_rolemaster FOREIGN KEY (roleid) REFERENCES rolemaster(roleid) ON DELETE CASCADE
                    );
                ");

                // Seed default roles if they do not exist
                int superAdminExists = con.ExecuteScalar<int>("SELECT COUNT(1) FROM rolemaster WHERE roleid = 3;");
                if (superAdminExists == 0)
                {
                    con.Execute("INSERT INTO rolemaster (roleid, rolename, normalizedname) VALUES (3, 'SuperAdmin', 'SUPERADMIN');");
                }
                else
                {
                    con.Execute("UPDATE rolemaster SET normalizedname = 'SUPERADMIN' WHERE roleid = 3;");
                }

                int adminExists = con.ExecuteScalar<int>("SELECT COUNT(1) FROM rolemaster WHERE roleid = 1;");
                if (adminExists == 0)
                {
                    con.Execute("INSERT INTO rolemaster (roleid, rolename, normalizedname) VALUES (1, 'Admin', 'ADMIN');");
                }
                else
                {
                    con.Execute("UPDATE rolemaster SET normalizedname = 'ADMIN' WHERE roleid = 1;");
                }

                int userExists = con.ExecuteScalar<int>("SELECT COUNT(1) FROM rolemaster WHERE roleid = 2;");
                if (userExists == 0)
                {
                    con.Execute("INSERT INTO rolemaster (roleid, rolename, normalizedname) VALUES (2, 'User', 'USER');");
                }
                else
                {
                    con.Execute("UPDATE rolemaster SET normalizedname = 'USER' WHERE roleid = 2;");
                }

                // Migrate user-to-role relationships
                con.Execute(@"
                    INSERT INTO aspnetuserroles (userid, roleid)
                    SELECT userid, roleid FROM usermaster
                    ON CONFLICT DO NOTHING;
                ");

                // Populate normalized columns and security stamps for migrated users
                var unnormalizedUsers = con.Query<(int UserId, string Username, string Email)>("SELECT userid, username, emailid FROM usermaster WHERE normalizedusername IS NULL OR normalizedusername = '' OR securitystamp IS NULL OR securitystamp = '';").ToList();
                foreach (var u in unnormalizedUsers)
                {
                    string normName = u.Username.ToUpperInvariant();
                    string normEmail = u.Email?.ToUpperInvariant() ?? string.Empty;
                    string stamp = Guid.NewGuid().ToString();
                    con.Execute(@"
                        UPDATE usermaster 
                        SET normalizedusername = @NormName, 
                            normalizedemail = @NormEmail, 
                            securitystamp = @Stamp,
                            concurrencystamp = @Stamp,
                            lockoutenabled = TRUE
                        WHERE userid = @UserId;", 
                        new { NormName = normName, NormEmail = normEmail, Stamp = stamp, UserId = u.UserId });
                }

                // Force lockout enabled for all users
                con.Execute("UPDATE usermaster SET lockoutenabled = TRUE WHERE lockoutenabled = FALSE OR lockoutenabled IS NULL;");

                // Create errorlogs table
                con.Execute(@"
                    CREATE TABLE IF NOT EXISTS errorlogs (
                        logid SERIAL PRIMARY KEY,
                        date_time TIMESTAMP NOT NULL,
                        last_occurred_on TIMESTAMP NOT NULL,
                        occurrence_count INTEGER DEFAULT 1,
                        username VARCHAR(256),
                        userid INTEGER,
                        role VARCHAR(256),
                        controller VARCHAR(256),
                        action VARCHAR(256),
                        request_url VARCHAR(2048),
                        http_method VARCHAR(16),
                        ip_address VARCHAR(64),
                        user_agent VARCHAR(1024),
                        exception_type VARCHAR(512),
                        exception_message TEXT,
                        inner_exception TEXT,
                        stack_trace TEXT,
                        status_code INTEGER,
                        severity VARCHAR(64),
                        correlation_id VARCHAR(64),
                        is_resolved BOOLEAN DEFAULT FALSE,
                        resolved_by VARCHAR(256),
                        resolved_on TIMESTAMP,
                        remarks TEXT
                    );
                ");
            }
            catch (System.Exception ex)
            {
                logger.LogError("Database", "Schema Migration", "Failed to run auto-migration for Identity tables/columns.", ex);
            }
        }

        public void SaveDocuments(UserDocumentModel document)
        {
            using var con = db.GetConnection();

            string sql = @"
            INSERT INTO UserDocuments
            (
                UserId,
                DocumentType,
                FileName,
                FilePath,
                Status,
                UploadedDate
            )
            VALUES
            (
                @UserId,
                @DocumentType,
                @FileName,
                @FilePath,
                'Pending',
                CURRENT_TIMESTAMP
            );";

            try
            {
                con.Execute(sql, document);
                logger.LogInfo("Document Management", "Upload Document", $"Document metadata saved: User ID {document.UserId}, Type: {document.DocumentType}, File: {document.FileName}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("Document Management", "Upload Document", $"Failed to save document metadata: User ID {document.UserId}, Type: {document.DocumentType}", ex);
                throw;
            }
        }

        public List<UserDocumentModel> GetUserDocuments(int userId)
        {
            using var con = db.GetConnection();

            string sql = @"
            SELECT
                DocumentId,
                UserId,
                DocumentType,
                FileName,
                FilePath,
                Status,
                UploadedDate
            FROM UserDocuments
            WHERE UserId = @UserId
            ORDER BY UploadedDate ASC";

            return con.Query<UserDocumentModel>(sql, new { UserId = userId }).ToList();
        }

        public List<UserDocumentModel> GetAllDocuments()
        {
            using var con = db.GetConnection();

            string sql = @"
            SELECT
                d.DocumentId,
                d.UserId,
                u.Username,
                d.DocumentType,
                d.FileName,
                d.FilePath,
                d.Status
            FROM UserDocuments d
            INNER JOIN UserMaster u ON d.UserId = u.UserId
            ORDER BY d.UserId ASC, d.UploadedDate ASC";

            return con.Query<UserDocumentModel>(sql).ToList();
        }

        public void ApproveDocument(int documentId, int verifiedBy)
        {
            using var con = db.GetConnection();

            string sql = @"
            UPDATE UserDocuments
            SET Status = 'Approved',
                VerifiedBy = @VerifiedBy,
                VerifiedDate = CURRENT_TIMESTAMP
            WHERE DocumentId = @DocumentId";

            try
            {
                con.Execute(sql, new { DocumentId = documentId, VerifiedBy = verifiedBy });
                logger.LogInfo("Document Verification", "Approve Document", $"Document ID {documentId} approved by Admin ID {verifiedBy}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("Document Verification", "Approve Document", $"Failed to approve Document ID {documentId} by Admin ID {verifiedBy}", ex);
                throw;
            }
        }

        public void RejectDocument(int documentId, int verifiedBy)
        {
            using var con = db.GetConnection();

            string sql = @"
            UPDATE UserDocuments
            SET Status = 'Rejected',
                VerifiedBy = @VerifiedBy,
                VerifiedDate = CURRENT_TIMESTAMP
            WHERE DocumentId = @DocumentId";

            try
            {
                con.Execute(sql, new { DocumentId = documentId, VerifiedBy = verifiedBy });
                logger.LogInfo("Document Verification", "Reject Document", $"Document ID {documentId} rejected by Admin ID {verifiedBy}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("Document Verification", "Reject Document", $"Failed to reject Document ID {documentId} by Admin ID {verifiedBy}", ex);
                throw;
            }
        }

        public void AddUser(UserModel user)
        {
            using var con = db.GetConnection();
            string sql = @"
            INSERT INTO UserMaster 
            (
                FullName, 
                Username, 
                Password, 
                EmailId, 
                MobileNo, 
                DOB, 
                RoleId, 
                Gender, 
                CreatedDate
            )
            VALUES 
            (
                @FullName, 
                @Username, 
                @Password, 
                @EmailId, 
                @MobileNo, 
                @DOB, 
                @RoleId, 
                @Gender, 
                @CreatedDate
            );";

            // Hash the password securely using BCrypt before storing it
            user.Password = BCrypt.Net.BCrypt.HashPassword(user.Password);

            try
            {
                con.Execute(sql, user);
                logger.LogInfo("User Registration", "Database Insert", $"User master record created for username: {user.Username}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("User Registration", "Database Insert", $"Failed to insert user master record for username: {user.Username}", ex);
                throw;
            }
        }

        public void EditUser(UserModel user)
        {
            using var con = db.GetConnection();
            string sql = @"
            UPDATE UserMaster
            SET FullName = @FullName,
                Username = @Username,
                EmailId = @EmailId,
                MobileNo = @MobileNo,
                RoleId = @RoleId
            WHERE UserId = @UserId;";

            try
            {
                con.Execute(sql, user);
                logger.LogInfo("User Management", "Database Update", $"User details updated for User ID: {user.UserId}, Username: {user.Username}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("User Management", "Database Update", $"Failed to update details for User ID: {user.UserId}", ex);
                throw;
            }
        }

        public void DeleteUser(int userId)
        {
            using var con = db.GetConnection();
            string sql = "DELETE FROM UserMaster WHERE UserId = @UserId;";

            try
            {
                con.Execute(sql, new { UserId = userId });
                logger.LogInfo("User Management", "Database Delete", $"User record deleted successfully for User ID: {userId}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("User Management", "Database Delete", $"Failed to delete user record for User ID: {userId}", ex);
                throw;
            }
        }

        public bool IsLastAdmin(int userId)
        {
            using var con = db.GetConnection();
            
            // Check if the user being deleted is indeed an Admin
            string checkRoleSql = "SELECT RoleId FROM UserMaster WHERE UserId = @UserId;";
            int roleId = con.ExecuteScalar<int>(checkRoleSql, new { UserId = userId });

            if (roleId != 1)
            {
                return false; // Not an admin
            }

            // Count remaining admins
            string countSql = "SELECT COUNT(1) FROM UserMaster WHERE RoleId = 1;";
            int adminCount = con.ExecuteScalar<int>(countSql);
            
            return adminCount <= 1;
        }

        public UserModel ValidateUser(string username, string password)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                UserId, 
                FullName, 
                Username, 
                Password, 
                EmailId, 
                MobileNo, 
                DOB::timestamp AS DOB, 
                RoleId, 
                Gender, 
                CreatedDate
            FROM UserMaster
            WHERE Username = @Username;";

            var user = con.QueryFirstOrDefault<UserModel>(sql, new { Username = username });

            // Verify password, supporting both secure BCrypt hashes and legacy plain-text passwords
            if (user != null)
            {
                bool isValid = false;
                string storedHash = user.Password ?? string.Empty;

                // BCrypt hashes start with $2a$, $2b$, or $2y$
                if (storedHash.StartsWith("$2a$") || storedHash.StartsWith("$2b$") || storedHash.StartsWith("$2y$"))
                {
                    try
                    {
                        isValid = BCrypt.Net.BCrypt.Verify(password, storedHash);
                    }
                    catch
                    {
                        isValid = (password == storedHash);
                    }
                }
                else
                {
                    // Fallback to legacy plain-text password check
                    isValid = (password == storedHash);
                }

                if (isValid)
                {
                    return user;
                }
            }

            return null!;
        }

        public bool IsUsernameExists(string username)
        {
            using var con = db.GetConnection();
            string sql = "SELECT COUNT(1) FROM UserMaster WHERE Username = @Username;";
            int count = con.ExecuteScalar<int>(sql, new { Username = username });
            return count > 0;
        }

        public UserModel GetUserByUsernameOrEmail(string usernameOrEmail)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                UserId, 
                FullName, 
                Username, 
                Password, 
                EmailId, 
                MobileNo, 
                DOB::timestamp AS DOB, 
                RoleId, 
                Gender, 
                CreatedDate
            FROM UserMaster
            WHERE Username = @Input OR EmailId = @Input;";

            return con.QueryFirstOrDefault<UserModel>(sql, new { Input = usernameOrEmail });
        }

        public UserModel GetUserById(int userId)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                UserId, 
                FullName, 
                Username, 
                Password, 
                EmailId, 
                MobileNo, 
                DOB::timestamp AS DOB, 
                RoleId, 
                Gender, 
                CreatedDate,
                ResetToken,
                ResetTokenExpiry
            FROM UserMaster
            WHERE UserId = @UserId;";

            return con.QueryFirstOrDefault<UserModel>(sql, new { UserId = userId });
        }

        public void UpdatePassword(int userId, string newPasswordHash)
        {
            using var con = db.GetConnection();
            string sql = "UPDATE UserMaster SET Password = @Password WHERE UserId = @UserId;";
            try
            {
                con.Execute(sql, new { Password = newPasswordHash, UserId = userId });
                logger.LogInfo("Password Reset", "Database Update", $"Password updated successfully in database for User ID: {userId}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("Password Reset", "Database Update", $"Failed to update password in database for User ID: {userId}", ex);
                throw;
            }
        }

        public UserModel GetUserByEmail(string email)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                UserId, 
                FullName, 
                Username, 
                Password, 
                EmailId, 
                MobileNo, 
                DOB::timestamp AS DOB, 
                RoleId, 
                Gender, 
                CreatedDate,
                ResetToken,
                ResetTokenExpiry
            FROM UserMaster
            WHERE EmailId = @Email;";

            return con.QueryFirstOrDefault<UserModel>(sql, new { Email = email });
        }

        public void SetResetToken(int userId, string token, System.DateTime expiry)
        {
            using var con = db.GetConnection();
            string sql = @"
            UPDATE UserMaster
            SET ResetToken = @Token,
                ResetTokenExpiry = @Expiry
            WHERE UserId = @UserId;";

            try
            {
                con.Execute(sql, new { Token = token, Expiry = expiry, UserId = userId });
                logger.LogInfo("Password Recovery", "Set Reset Token", $"Reset token registered for User ID: {userId}, Expiry: {expiry}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("Password Recovery", "Set Reset Token", $"Failed to set reset token for User ID: {userId}", ex);
                throw;
            }
        }

        public UserModel GetUserByResetToken(string token)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                UserId, 
                FullName, 
                Username, 
                Password, 
                EmailId, 
                MobileNo, 
                DOB::timestamp AS DOB, 
                RoleId, 
                Gender, 
                CreatedDate,
                ResetToken,
                ResetTokenExpiry
            FROM UserMaster
            WHERE ResetToken = @Token;";

            return con.QueryFirstOrDefault<UserModel>(sql, new { Token = token });
        }

        public void ClearResetToken(int userId)
        {
            using var con = db.GetConnection();
            string sql = @"
            UPDATE UserMaster
            SET ResetToken = NULL,
                ResetTokenExpiry = NULL
            WHERE UserId = @UserId;";

            try
            {
                con.Execute(sql, new { UserId = userId });
                logger.LogInfo("Password Recovery", "Clear Reset Token", $"Reset token cleared for User ID: {userId}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("Password Recovery", "Clear Reset Token", $"Failed to clear reset token for User ID: {userId}", ex);
                throw;
            }
        }

        public void DeleteDocument(int documentId)
        {
            using var con = db.GetConnection();
            string sql = "DELETE FROM UserDocuments WHERE DocumentId = @DocumentId;";
            try
            {
                con.Execute(sql, new { DocumentId = documentId });
                logger.LogInfo("Document Management", "Database Delete", $"Document record deleted for Document ID: {documentId}");
            }
            catch (System.Exception ex)
            {
                logger.LogError("Document Management", "Database Delete", $"Failed to delete document record for Document ID: {documentId}", ex);
                throw;
            }
        }

        public void ReplaceDocument(int documentId, string newFileName, string newFilePath)
        {
            using var con = db.GetConnection();
            string sql = @"
            UPDATE UserDocuments
            SET FileName = @FileName,
                FilePath = @FilePath,
                Status = 'Pending',
                UploadedDate = CURRENT_TIMESTAMP,
                VerifiedBy = NULL,
                VerifiedDate = NULL
            WHERE DocumentId = @DocumentId;";

            try
            {
                con.Execute(sql, new { DocumentId = documentId, FileName = newFileName, FilePath = newFilePath });
                logger.LogInfo("Document Management", "Replace Document", $"Document ID {documentId} replaced with new file {newFileName} in database");
            }
            catch (System.Exception ex)
            {
                logger.LogError("Document Management", "Replace Document", $"Failed to replace Document ID {documentId} with new file {newFileName} in database", ex);
                throw;
            }
        }
    }
}