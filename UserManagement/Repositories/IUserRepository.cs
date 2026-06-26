using UserManagement.Models;
using System.Collections.Generic;

namespace UserManagement.Repositories
{
    public interface IUserRepository
    {
        void AddUser(UserModel user);
        void EditUser(UserModel user);
        void DeleteUser(int userId);
        bool IsLastAdmin(int userId);

        UserModel ValidateUser(string username, string password);
        bool IsUsernameExists(string username);
        UserModel GetUserByUsernameOrEmail(string usernameOrEmail);
        UserModel GetUserById(int userId);
        void UpdatePassword(int userId, string newPasswordHash);
        UserModel GetUserByEmail(string email);
        void SetResetToken(int userId, string token, System.DateTime expiry);
        UserModel GetUserByResetToken(string token);
        void ClearResetToken(int userId);

        void SaveDocuments(UserDocumentModel document);

        List<UserDocumentModel> GetUserDocuments(int userId);

        List<UserDocumentModel> GetAllDocuments();

        void ApproveDocument(int documentId, int verifiedBy);
        void RejectDocument(int documentId, int verifiedBy);

        void DeleteDocument(int documentId);
        void ReplaceDocument(int documentId, string newFileName, string newFilePath);
    }
}