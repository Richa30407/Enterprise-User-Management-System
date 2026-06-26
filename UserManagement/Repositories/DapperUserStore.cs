using Dapper;
using Microsoft.AspNetCore.Identity;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using UserManagement.Models;

namespace UserManagement.Repositories
{
    public class DapperUserStore : 
        IUserStore<ApplicationUser>,
        IUserPasswordStore<ApplicationUser>,
        IUserEmailStore<ApplicationUser>,
        IUserPhoneNumberStore<ApplicationUser>,
        IUserLockoutStore<ApplicationUser>,
        IUserSecurityStampStore<ApplicationUser>,
        IUserRoleStore<ApplicationUser>
    {
        private readonly DBHelper db = new DBHelper();

        public void Dispose()
        {
            // Nothing to dispose
        }

        // --- IUserStore ---

        public async Task<string> GetUserIdAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.Id.ToString();
        }

        public async Task<string?> GetUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.UserName;
        }

        public async Task SetUserNameAsync(ApplicationUser user, string? userName, CancellationToken cancellationToken)
        {
            user.UserName = userName ?? string.Empty;
        }

        public async Task<string?> GetNormalizedUserNameAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.NormalizedUserName;
        }

        public async Task SetNormalizedUserNameAsync(ApplicationUser user, string? normalizedName, CancellationToken cancellationToken)
        {
            user.NormalizedUserName = normalizedName;
        }

        public async Task<IdentityResult> CreateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            INSERT INTO usermaster 
            (
                fullname, 
                username, 
                password, 
                emailid, 
                mobileno, 
                dob, 
                roleid, 
                gender, 
                createddate,
                normalizedusername,
                normalizedemail,
                emailconfirmed,
                securitystamp,
                concurrencystamp,
                phonenumberconfirmed,
                twofactorenabled,
                lockoutend,
                lockoutenabled,
                accessfailedcount
            )
            VALUES 
            (
                @FullName, 
                @UserName, 
                @PasswordHash, 
                @Email, 
                @PhoneNumber, 
                @DOB, 
                @RoleId, 
                @Gender, 
                @CreatedDate,
                @NormalizedUserName,
                @NormalizedEmail,
                @EmailConfirmed,
                @SecurityStamp,
                @ConcurrencyStamp,
                @PhoneNumberConfirmed,
                @TwoFactorEnabled,
                @LockoutEnd,
                @LockoutEnabled,
                @AccessFailedCount
            )
            RETURNING userid;";

            try
            {
                int id = await con.ExecuteScalarAsync<int>(sql, user);
                user.Id = id;
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<IdentityResult> UpdateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            UPDATE usermaster
            SET fullname = @FullName,
                username = @UserName,
                password = @PasswordHash,
                emailid = @Email,
                mobileno = @PhoneNumber,
                dob = @DOB,
                roleid = @RoleId,
                gender = @Gender,
                normalizedusername = @NormalizedUserName,
                normalizedemail = @NormalizedEmail,
                emailconfirmed = @EmailConfirmed,
                securitystamp = @SecurityStamp,
                concurrencystamp = @ConcurrencyStamp,
                phonenumberconfirmed = @PhoneNumberConfirmed,
                twofactorenabled = @TwoFactorEnabled,
                lockoutend = @LockoutEnd,
                lockoutenabled = @LockoutEnabled,
                accessfailedcount = @AccessFailedCount,
                resettoken = @ResetToken,
                resettokenexpiry = @ResetTokenExpiry
            WHERE userid = @Id;";

            try
            {
                await con.ExecuteAsync(sql, user);
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<IdentityResult> DeleteAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = "DELETE FROM usermaster WHERE userid = @Id;";
            try
            {
                await con.ExecuteAsync(sql, new { Id = user.Id });
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<ApplicationUser?> FindByIdAsync(string userId, CancellationToken cancellationToken)
        {
            if (!int.TryParse(userId, out int id)) return null;
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                userid AS Id, 
                fullname AS FullName, 
                username AS UserName, 
                password AS PasswordHash, 
                emailid AS Email, 
                mobileno AS PhoneNumber, 
                dob::timestamp AS DOB, 
                roleid AS RoleId, 
                gender AS Gender, 
                createddate AS CreatedDate,
                normalizedusername AS NormalizedUserName,
                normalizedemail AS NormalizedEmail,
                emailconfirmed AS EmailConfirmed,
                securitystamp AS SecurityStamp,
                concurrencystamp AS ConcurrencyStamp,
                phonenumberconfirmed AS PhoneNumberConfirmed,
                twofactorenabled AS TwoFactorEnabled,
                lockoutend AS LockoutEnd,
                lockoutenabled AS LockoutEnabled,
                accessfailedcount AS AccessFailedCount,
                resettoken AS ResetToken,
                resettokenexpiry AS ResetTokenExpiry
            FROM usermaster
            WHERE userid = @Id;";
            return await con.QueryFirstOrDefaultAsync<ApplicationUser>(sql, new { Id = id });
        }

        public async Task<ApplicationUser?> FindByNameAsync(string normalizedUserName, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                userid AS Id, 
                fullname AS FullName, 
                username AS UserName, 
                password AS PasswordHash, 
                emailid AS Email, 
                mobileno AS PhoneNumber, 
                dob::timestamp AS DOB, 
                roleid AS RoleId, 
                gender AS Gender, 
                createddate AS CreatedDate,
                normalizedusername AS NormalizedUserName,
                normalizedemail AS NormalizedEmail,
                emailconfirmed AS EmailConfirmed,
                securitystamp AS SecurityStamp,
                concurrencystamp AS ConcurrencyStamp,
                phonenumberconfirmed AS PhoneNumberConfirmed,
                twofactorenabled AS TwoFactorEnabled,
                lockoutend AS LockoutEnd,
                lockoutenabled AS LockoutEnabled,
                accessfailedcount AS AccessFailedCount,
                resettoken AS ResetToken,
                resettokenexpiry AS ResetTokenExpiry
            FROM usermaster
            WHERE normalizedusername = @Name;";
            return await con.QueryFirstOrDefaultAsync<ApplicationUser>(sql, new { Name = normalizedUserName });
        }

        // --- IUserPasswordStore ---

        public async Task SetPasswordHashAsync(ApplicationUser user, string? passwordHash, CancellationToken cancellationToken)
        {
            user.PasswordHash = passwordHash;
        }

        public async Task<string?> GetPasswordHashAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.PasswordHash;
        }

        public async Task<bool> HasPasswordAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return !string.IsNullOrEmpty(user.PasswordHash);
        }

        // --- IUserEmailStore ---

        public async Task SetEmailAsync(ApplicationUser user, string? email, CancellationToken cancellationToken)
        {
            user.Email = email;
        }

        public async Task<string?> GetEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.Email;
        }

        public async Task<bool> GetEmailConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.EmailConfirmed;
        }

        public async Task SetEmailConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.EmailConfirmed = confirmed;
        }

        public async Task<ApplicationUser?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                userid AS Id, 
                fullname AS FullName, 
                username AS UserName, 
                password AS PasswordHash, 
                emailid AS Email, 
                mobileno AS PhoneNumber, 
                dob::timestamp AS DOB, 
                roleid AS RoleId, 
                gender AS Gender, 
                createddate AS CreatedDate,
                normalizedusername AS NormalizedUserName,
                normalizedemail AS NormalizedEmail,
                emailconfirmed AS EmailConfirmed,
                securitystamp AS SecurityStamp,
                concurrencystamp AS ConcurrencyStamp,
                phonenumberconfirmed AS PhoneNumberConfirmed,
                twofactorenabled AS TwoFactorEnabled,
                lockoutend AS LockoutEnd,
                lockoutenabled AS LockoutEnabled,
                accessfailedcount AS AccessFailedCount,
                resettoken AS ResetToken,
                resettokenexpiry AS ResetTokenExpiry
            FROM usermaster
            WHERE normalizedemail = @Email;";
            return await con.QueryFirstOrDefaultAsync<ApplicationUser>(sql, new { Email = normalizedEmail });
        }

        public async Task<string?> GetNormalizedEmailAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.NormalizedEmail;
        }

        public async Task SetNormalizedEmailAsync(ApplicationUser user, string? normalizedEmail, CancellationToken cancellationToken)
        {
            user.NormalizedEmail = normalizedEmail;
        }

        // --- IUserPhoneNumberStore ---

        public async Task SetPhoneNumberAsync(ApplicationUser user, string? phoneNumber, CancellationToken cancellationToken)
        {
            user.PhoneNumber = phoneNumber;
        }

        public async Task<string?> GetPhoneNumberAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.PhoneNumber;
        }

        public async Task<bool> GetPhoneNumberConfirmedAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.PhoneNumberConfirmed;
        }

        public async Task SetPhoneNumberConfirmedAsync(ApplicationUser user, bool confirmed, CancellationToken cancellationToken)
        {
            user.PhoneNumberConfirmed = confirmed;
        }

        // --- IUserLockoutStore ---

        public async Task<DateTimeOffset?> GetLockoutEndDateAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.LockoutEnd;
        }

        public async Task SetLockoutEndDateAsync(ApplicationUser user, DateTimeOffset? lockoutEnd, CancellationToken cancellationToken)
        {
            user.LockoutEnd = lockoutEnd;
        }

        public async Task<int> IncrementAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            user.AccessFailedCount++;
            return user.AccessFailedCount;
        }

        public async Task ResetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            user.AccessFailedCount = 0;
        }

        public async Task<int> GetAccessFailedCountAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.AccessFailedCount;
        }

        public async Task<bool> GetLockoutEnabledAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.LockoutEnabled;
        }

        public async Task SetLockoutEnabledAsync(ApplicationUser user, bool enabled, CancellationToken cancellationToken)
        {
            user.LockoutEnabled = enabled;
        }

        // --- IUserSecurityStampStore ---

        public async Task SetSecurityStampAsync(ApplicationUser user, string stamp, CancellationToken cancellationToken)
        {
            user.SecurityStamp = stamp;
        }

        public async Task<string?> GetSecurityStampAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            return user.SecurityStamp;
        }

        // --- IUserRoleStore ---

        public async Task AddToRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            int roleId = await con.ExecuteScalarAsync<int>("SELECT roleid FROM rolemaster WHERE rolename = @Name;", new { Name = roleName });
            if (roleId > 0)
            {
                user.RoleId = roleId;
                await con.ExecuteAsync("UPDATE usermaster SET roleid = @RoleId WHERE userid = @UserId;", new { RoleId = roleId, UserId = user.Id });

                string sql = "INSERT INTO aspnetuserroles (userid, roleid) VALUES (@UserId, @RoleId) ON CONFLICT DO NOTHING;";
                await con.ExecuteAsync(sql, new { UserId = user.Id, RoleId = roleId });
            }
        }

        public async Task RemoveFromRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            int roleId = await con.ExecuteScalarAsync<int>("SELECT roleid FROM rolemaster WHERE rolename = @Name;", new { Name = roleName });
            if (roleId > 0)
            {
                string sql = "DELETE FROM aspnetuserroles WHERE userid = @UserId AND roleid = @RoleId;";
                await con.ExecuteAsync(sql, new { UserId = user.Id, RoleId = roleId });
            }
        }

        public async Task<IList<string>> GetRolesAsync(ApplicationUser user, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT r.rolename 
            FROM rolemaster r
            INNER JOIN aspnetuserroles ur ON r.roleid = ur.roleid
            WHERE ur.userid = @UserId;";
            var roles = await con.QueryAsync<string>(sql, new { UserId = user.Id });
            return roles.ToList();
        }

        public async Task<bool> IsInRoleAsync(ApplicationUser user, string roleName, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT COUNT(1) 
            FROM rolemaster r
            INNER JOIN aspnetuserroles ur ON r.roleid = ur.roleid
            WHERE ur.userid = @UserId AND r.rolename = @RoleName;";
            int count = await con.ExecuteScalarAsync<int>(sql, new { UserId = user.Id, RoleName = roleName });
            return count > 0;
        }

        public async Task<IList<ApplicationUser>> GetUsersInRoleAsync(string roleName, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                u.userid AS Id, 
                u.fullname AS FullName, 
                u.username AS UserName, 
                u.password AS PasswordHash, 
                u.emailid AS Email, 
                u.mobileno AS PhoneNumber, 
                u.dob::timestamp AS DOB, 
                u.roleid AS RoleId, 
                u.gender AS Gender, 
                u.createddate AS CreatedDate,
                u.normalizedusername AS NormalizedUserName,
                u.normalizedemail AS NormalizedEmail,
                u.emailconfirmed AS EmailConfirmed,
                u.securitystamp AS SecurityStamp,
                u.concurrencystamp AS ConcurrencyStamp,
                u.phonenumberconfirmed AS PhoneNumberConfirmed,
                u.twofactorenabled AS TwoFactorEnabled,
                u.lockoutend AS LockoutEnd,
                u.lockoutenabled AS LockoutEnabled,
                u.accessfailedcount AS AccessFailedCount,
                u.resettoken AS ResetToken,
                u.resettokenexpiry AS ResetTokenExpiry
            FROM usermaster u
            INNER JOIN aspnetuserroles ur ON u.userid = ur.userid
            INNER JOIN rolemaster r ON ur.roleid = r.roleid
            WHERE r.rolename = @RoleName;";
            var users = await con.QueryAsync<ApplicationUser>(sql, new { RoleName = roleName });
            return users.ToList();
        }
    }
}
