using Npgsql;
using System.Data;

namespace UserManagement.Models
{
    public class DBHelper
    {
        private readonly string connectionString =
            "Host=localhost;Port=5432;Database=UserManagementDB;Username=postgres;Password=300407";

        public NpgsqlConnection GetConnection()
        {
            return new NpgsqlConnection(connectionString);
        }
    }
}