using Microsoft.AspNetCore.Http;
using System;

namespace UserManagement.Models
{
    public class UserDocumentModel
    {
        public int DocumentId { get; set; }
        public int UserId { get; set; }

        public string? Username { get; set; }

        public string? DocumentType { get; set; } // Aadhaar / PAN / Other
        public string? FileName { get; set; }
        public string? FilePath { get; set; }

        public string? Status { get; set; } = "Pending";

        public DateTime? UploadedDate { get; set; }
        public int? VerifiedBy { get; set; }
        public DateTime? VerifiedDate { get; set; }

        // Upload fields
        public IFormFile? AadhaarFile { get; set; }
        public IFormFile? PanFile { get; set; }
        public IFormFile? OtherFile { get; set; }
    }
}