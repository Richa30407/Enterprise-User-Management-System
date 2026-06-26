using System;
using System.Collections.Generic;

namespace UserManagement.Models
{
    public class ErrorLogViewModel
    {
        public int LogId { get; set; }
        public DateTime DateTime { get; set; }
        public DateTime LastOccurredOn { get; set; }
        public int OccurrenceCount { get; set; }
        public string? Username { get; set; }
        public int? UserId { get; set; }
        public string? Role { get; set; }
        public string? Controller { get; set; }
        public string? Action { get; set; }
        public string? RequestUrl { get; set; }
        public string? HttpMethod { get; set; }
        public string? IpAddress { get; set; }
        public string? UserAgent { get; set; }
        public string? ExceptionType { get; set; }
        public string? ExceptionMessage { get; set; }
        public string? InnerException { get; set; }
        public string? StackTrace { get; set; }
        public int StatusCode { get; set; }
        public string? Severity { get; set; }
        public string? CorrelationId { get; set; }
        public bool IsResolved { get; set; }
        public string? ResolvedBy { get; set; }
        public DateTime? ResolvedOn { get; set; }
        public string? Remarks { get; set; }
    }

    public class ErrorLogsListViewModel
    {
        public List<ErrorLogViewModel> Logs { get; set; } = new();
        public int TotalItems { get; set; }
        public int PageNumber { get; set; }
        public int PageSize { get; set; }
        public int TotalPages => (int)Math.Ceiling((double)TotalItems / PageSize);
        
        // Filters & Search
        public string? Search { get; set; }
        public string? Severity { get; set; }
        public string? ExceptionType { get; set; }
        public string? DateRange { get; set; } // Today, Yesterday, Last7Days, Last30Days, Custom
        public string? StartDate { get; set; } // yyyy-MM-dd
        public string? EndDate { get; set; }   // yyyy-MM-dd
        public string? ResolutionStatus { get; set; } // All, Resolved, Unresolved
        public string? SortOrder { get; set; }

        // Dashboard Stats
        public int TotalErrorsCount { get; set; }
        public int TodaysErrorsCount { get; set; }
        public int CriticalErrorsCount { get; set; }
        public int ResolvedErrorsCount { get; set; }

        // Filter Options Dropdowns
        public List<string> ExceptionTypes { get; set; } = new();
        public List<string> Severities { get; set; } = new();
    }
}
