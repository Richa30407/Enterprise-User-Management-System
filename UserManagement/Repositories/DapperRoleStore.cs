using Dapper;
using Microsoft.AspNetCore.Identity;
using System;
using System.Threading;
using System.Threading.Tasks;
using UserManagement.Models;

namespace UserManagement.Repositories
{
    public class DapperRoleStore : IRoleStore<ApplicationRole>
    {
        private readonly DBHelper db = new DBHelper();

        public void Dispose()
        {
            // Nothing to dispose
        }

        public async Task<IdentityResult> CreateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            INSERT INTO rolemaster (rolename, normalizedname, concurrencystamp)
            VALUES (@Name, @NormalizedName, @ConcurrencyStamp)
            RETURNING roleid;";

            try
            {
                int id = await con.ExecuteScalarAsync<int>(sql, role);
                role.Id = id;
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<IdentityResult> UpdateAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            UPDATE rolemaster
            SET rolename = @Name,
                normalizedname = @NormalizedName,
                concurrencystamp = @ConcurrencyStamp
            WHERE roleid = @Id;";

            try
            {
                await con.ExecuteAsync(sql, role);
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<IdentityResult> DeleteAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = "DELETE FROM rolemaster WHERE roleid = @Id;";
            try
            {
                await con.ExecuteAsync(sql, new { Id = role.Id });
                return IdentityResult.Success;
            }
            catch (Exception ex)
            {
                return IdentityResult.Failed(new IdentityError { Description = ex.Message });
            }
        }

        public async Task<string> GetRoleIdAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            return role.Id.ToString();
        }

        public async Task<string?> GetRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            return role.Name;
        }

        public async Task SetRoleNameAsync(ApplicationRole role, string? roleName, CancellationToken cancellationToken)
        {
            role.Name = roleName;
        }

        public async Task<string?> GetNormalizedRoleNameAsync(ApplicationRole role, CancellationToken cancellationToken)
        {
            return role.NormalizedName;
        }

        public async Task SetNormalizedRoleNameAsync(ApplicationRole role, string? normalizedName, CancellationToken cancellationToken)
        {
            role.NormalizedName = normalizedName;
        }

        public async Task<ApplicationRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            if (!int.TryParse(roleId, out int id)) return null;
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                roleid AS Id, 
                rolename AS Name, 
                normalizedname AS NormalizedName, 
                concurrencystamp AS ConcurrencyStamp
            FROM rolemaster
            WHERE roleid = @Id;";
            return await con.QueryFirstOrDefaultAsync<ApplicationRole>(sql, new { Id = id });
        }

        public async Task<ApplicationRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            using var con = db.GetConnection();
            string sql = @"
            SELECT 
                roleid AS Id, 
                rolename AS Name, 
                normalizedname AS NormalizedName, 
                concurrencystamp AS ConcurrencyStamp
            FROM rolemaster
            WHERE normalizedname = @Name;";
            return await con.QueryFirstOrDefaultAsync<ApplicationRole>(sql, new { Name = normalizedRoleName });
        }
    }
}
