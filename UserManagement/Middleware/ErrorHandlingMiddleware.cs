using Microsoft.AspNetCore.Http;
using System;
using System.Threading.Tasks;
using UserManagement.Services;
using UserManagement.Models;
using Microsoft.Extensions.DependencyInjection;
using UserManagement.Repositories;
using Dapper;
using Npgsql;
using System.IO;
using System.Collections.Generic;

namespace UserManagement.Middleware
{
    public class ErrorHandlingMiddleware
    {
        private readonly RequestDelegate _next;

        public ErrorHandlingMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                await LogAndHandleExceptionAsync(context, ex);
            }
        }

        private async Task LogAndHandleExceptionAsync(HttpContext context, Exception exception)
        {
            var correlationId = Guid.NewGuid().ToString();
            var now = DateTime.Now;

            // Extract Request Details
            var requestUrl = $"{context.Request.Path}{context.Request.QueryString}";
            var httpMethod = context.Request.Method;
            var ipAddress = context.Connection.RemoteIpAddress?.ToString() ?? "N/A";
            var userAgent = context.Request.Headers["User-Agent"].ToString() ?? "N/A";

            // Extract User Details (if available)
            string? username = null;
            int? userId = null;
            string? role = null;

            if (context.User?.Identity?.IsAuthenticated == true)
            {
                username = context.User.Identity.Name;
                
                var userIdClaim = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier);
                if (userIdClaim != null && int.TryParse(userIdClaim.Value, out int uid))
                {
                    userId = uid;
                }

                if (context.User.IsInRole("SuperAdmin")) role = "SuperAdmin";
                else if (context.User.IsInRole("Admin")) role = "Admin";
                else if (context.User.IsInRole("User")) role = "User";
            }

            // Extract Controller/Action from RouteData
            var routeValues = context.Request.RouteValues;
            string controller = routeValues["controller"]?.ToString() ?? "Unknown";
            string action = routeValues["action"]?.ToString() ?? "Unknown";

            // Automatically Classify Severity
            string severity = ClassifySeverity(exception);

            // Log exception to existing logging system
            var logger = context.RequestServices.GetRequiredService<IAppLogger>();
            logger.LogError(controller, action, $"Unhandled Exception [Severity: {severity}] (Correlation ID: {correlationId}): {exception.Message}", exception);

            // Save to database errorlogs table with deduplication check
            try
            {
                using var con = new DBHelper().GetConnection();
                con.Open();

                string exceptionType = exception.GetType().FullName ?? "UnknownException";
                string exceptionMessage = exception.Message;

                // Check for existing unresolved duplicate exception
                string checkSql = @"
                    SELECT logid 
                    FROM errorlogs 
                    WHERE exception_type = @ExceptionType 
                      AND exception_message = @ExceptionMessage 
                      AND controller = @Controller 
                      AND action = @Action 
                      AND is_resolved = FALSE 
                    LIMIT 1;";

                int? existingLogId = await con.QueryFirstOrDefaultAsync<int?>(checkSql, new
                {
                    ExceptionType = exceptionType,
                    ExceptionMessage = exceptionMessage,
                    Controller = controller,
                    Action = action
                });

                if (existingLogId.HasValue)
                {
                    // Update existing duplicate
                    string updateSql = @"
                        UPDATE errorlogs 
                        SET occurrence_count = occurrence_count + 1, 
                            last_occurred_on = @Now,
                            correlation_id = @CorrelationId,
                            username = COALESCE(@Username, username),
                            userid = COALESCE(@UserId, userid),
                            role = COALESCE(@Role, role),
                            ip_address = @IpAddress,
                            user_agent = @UserAgent
                        WHERE logid = @LogId;";

                    await con.ExecuteAsync(updateSql, new
                    {
                        Now = now,
                        CorrelationId = correlationId,
                        Username = username,
                        UserId = userId,
                        Role = role,
                        IpAddress = ipAddress,
                        UserAgent = userAgent,
                        LogId = existingLogId.Value
                    });
                }
                else
                {
                    // Insert new log
                    string insertSql = @"
                        INSERT INTO errorlogs 
                        (
                            date_time, last_occurred_on, occurrence_count, username, userid, role, 
                            controller, action, request_url, http_method, ip_address, user_agent, 
                            exception_type, exception_message, inner_exception, stack_trace, 
                            status_code, severity, correlation_id, is_resolved
                        )
                        VALUES 
                        (
                            @Now, @Now, 1, @Username, @UserId, @Role, 
                            @Controller, @Action, @RequestUrl, @HttpMethod, @IpAddress, @UserAgent, 
                            @ExceptionType, @ExceptionMessage, @InnerException, @StackTrace, 
                            @StatusCode, @Severity, @CorrelationId, FALSE
                        );";

                    await con.ExecuteAsync(insertSql, new
                    {
                        Now = now,
                        Username = username,
                        UserId = userId,
                        Role = role,
                        Controller = controller,
                        Action = action,
                        RequestUrl = requestUrl,
                        HttpMethod = httpMethod,
                        IpAddress = ipAddress,
                        UserAgent = userAgent,
                        ExceptionType = exceptionType,
                        ExceptionMessage = exceptionMessage,
                        InnerException = exception.InnerException?.Message,
                        StackTrace = exception.StackTrace,
                        StatusCode = 500,
                        Severity = severity,
                        CorrelationId = correlationId
                    });
                }
            }
            catch (Exception dbEx)
            {
                // Fallback log if database save fails
                logger.LogError("Database", "SaveErrorLog", $"Failed to save/update error log in database: {dbEx.Message}", dbEx);
            }

            // If the error occurred on the error page itself or status code handler, prevent infinite redirect loop
            var path = context.Request.Path.Value ?? "";
            if (path.Contains("/Home/Error", StringComparison.OrdinalIgnoreCase) || 
                path.Contains("/Home/StatusCodeHandler", StringComparison.OrdinalIgnoreCase))
            {
                context.Response.StatusCode = 500;
                context.Response.ContentType = "text/html";
                await context.Response.WriteAsync($"<html><head><title>Internal Server Error</title></head><body style=\"font-family: sans-serif; padding: 20px; background-color: #f8d7da; color: #721c24;\"><h1>Internal Server Error</h1><p>An unexpected error occurred while processing your request.</p><p>Correlation ID: {correlationId}</p></body></html>");
                return;
            }

            // Redirect user to the friendly error page
            context.Response.Redirect($"/Home/Error?correlationId={Uri.EscapeDataString(correlationId)}");

        }

        private string ClassifySeverity(Exception exception)
        {
            if (exception is NpgsqlException || 
                exception is System.Data.Common.DbException || 
                exception is AccessViolationException || 
                exception is NullReferenceException)
            {
                return "Critical";
            }
            
            if (exception is InvalidOperationException || 
                exception is KeyNotFoundException)
            {
                return "High";
            }
            
            if (exception is ArgumentException || 
                exception is TimeoutException || 
                exception is IOException)
            {
                return "Medium";
            }
            
            return "Low";
        }
    }
}
