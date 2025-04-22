using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

namespace DatabricksOAuthDemo
{
    // ─────────────────────────────────────────────
    // MODELS
    // ─────────────────────────────────────────────

    public enum AuthType { U2M, M2M, PAT }

    public record M2MRequest(
        [property: JsonPropertyName("client_id")]     string ClientId,
        [property: JsonPropertyName("client_secret")] string ClientSecret
    );

    public record TokenResponseInitial(
        [property: JsonPropertyName("access_token")]  string AccessToken,
        [property: JsonPropertyName("refresh_token")] string RefreshToken,
        [property: JsonPropertyName("expires_in")]    int    ExpiresIn
    );
    public record Trip(long TripCount, string? PickupZip);



    // ─────────────────────────────────────────────
    // REPO
    // ─────────────────────────────────────────────

    class DatabricksRepo
    {
        private readonly IHttpClientFactory _httpFactory;
        private readonly string _workspaceUrl, _warehouseId;

        public DatabricksRepo(
            IHttpClientFactory httpFactory,
            string workspaceUrl,
            string warehouseId)
        {
            _httpFactory  = httpFactory;
            _workspaceUrl = workspaceUrl;
            _warehouseId  = warehouseId;
        }

        public async Task<IEnumerable<Trip>> QueryAsync(string accessToken, string statement)
        {
            var client = _httpFactory.CreateClient();
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", accessToken);

            var payload = new { statement, warehouse_id = _warehouseId };
            var resp    = await client.PostAsJsonAsync(
                $"https://{_workspaceUrl}/api/2.0/sql/statements",
                payload);
            resp.EnsureSuccessStatusCode();

            using var doc = await resp.Content.ReadFromJsonAsync<JsonDocument>()
                            ?? throw new Exception("Invalid JSON");

            return doc.RootElement
                      .GetProperty("result")
                      .GetProperty("data_array")
                      .EnumerateArray()
                      .Select(e => new Trip(
                          int.Parse(e[0].GetString() ?? "0"),
                          e[1].GetString()
                      ))
                      .ToList();
        }
    }

    // ─────────────────────────────────────────────
    // PROGRAM
    // ─────────────────────────────────────────────

    public class Program
    {
        public static async Task<string> GetRefreshToken(HttpContext ctx, string tokenUrl)
        {
            var accessToken  = ctx.Session.GetString("auth_access_token");
            var refreshToken = ctx.Session.GetString("auth_refresh_token");
            var expiresAtStr = ctx.Session.GetString("auth_expires_at");

            if (string.IsNullOrEmpty(accessToken)
                || string.IsNullOrEmpty(expiresAtStr)
                || DateTimeOffset.UtcNow >= DateTimeOffset.Parse(expiresAtStr))
            {
                // need to refresh
                if (string.IsNullOrEmpty(refreshToken))
                    throw new InvalidOperationException("Missing refresh token in session.");

                var clientId     = ctx.Session.GetString("auth_client_id")!;
                var clientSecret = ctx.Session.GetString("auth_client_secret")!;
                var form = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string,string>("grant_type",    "refresh_token"),
                    new KeyValuePair<string,string>("refresh_token", refreshToken),
                    new KeyValuePair<string,string>("client_id",     clientId),
                    new KeyValuePair<string,string>("client_secret", clientSecret),
                });

                var client = ctx.RequestServices
                                .GetRequiredService<IHttpClientFactory>()
                                .CreateClient();

                var resp   = await client.PostAsync(tokenUrl, form);
                resp.EnsureSuccessStatusCode();

                var tk = await resp.Content.ReadFromJsonAsync<TokenResponseInitial>()
                         ?? throw new Exception("Failed to parse refresh response.");

                accessToken  = tk.AccessToken;
                refreshToken = tk.RefreshToken;
                var expiresAt = DateTimeOffset.UtcNow.AddSeconds(tk.ExpiresIn - 60);

                ctx.Session.SetString("auth_access_token",  accessToken);
                ctx.Session.SetString("auth_refresh_token", refreshToken);
                ctx.Session.SetString("auth_expires_at",    expiresAt.ToString("o"));
            }

            return accessToken!;
        }
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // session + http client
            builder.Services.AddHttpClient();
            builder.Services.AddDistributedMemoryCache();
            builder.Services.AddSession(options =>
            {
                options.IdleTimeout        = TimeSpan.FromMinutes(30);
                options.Cookie.HttpOnly    = true;
                options.Cookie.IsEssential = true;
            });

            var app = builder.Build();
            app.UseSession();

            // config
            var workspaceUrl = builder.Configuration["WORKSPACE_URL"]
                               ?? throw new Exception("Missing WORKSPACE_URL");
            var warehouseId  = builder.Configuration["WAREHOUSE_ID"]
                               ?? throw new Exception("Missing WAREHOUSE_ID");
            var tokenUrl     = $"https://{workspaceUrl}/oidc/v1/token";
            var authUrl      = $"https://{workspaceUrl}/oidc/v1/authorize";

            // ─── U2M start ────────────────────────────────────
            app.MapGet("/auth", async (HttpContext ctx) =>
            {
                var q = ctx.Request.Query;
                var cid  = q["client_id"].ToString();
                var csec = q["client_secret"].ToString();
                var ruri = q["redirect_uri"].ToString() ?? string.Empty;
                var type = q["auth_type"].ToString();
                var pat = q["pat"].ToString() ?? string.Empty;


                // stash for callback
                ctx.Session.SetString("auth_client_id",     cid);
                ctx.Session.SetString("auth_client_secret", csec);
                ctx.Session.SetString("auth_redirect_uri",  ruri);
                ctx.Session.SetString("auth_pat",  ruri);
                ctx.Session.SetString("auth_auth_type",  type);

                if (type == "PAT") {
                    return Results.Redirect("/?type=pat");
                } else if (type == "U2M" ) {

                    var qs = new Dictionary<string, string?> {
                        ["response_type"] = "code",
                        ["client_id"]     = cid,
                        ["redirect_uri"]  = ruri,
                        ["scope"]         = "sql offline_access"
                    };

                    var url = QueryHelpers.AddQueryString(authUrl, qs);
                    return Results.Redirect(url);

                }   else if (type == "M2M") {

                    var form = new FormUrlEncodedContent(new[]
                    {
                        new KeyValuePair<string,string>("grant_type",    "client_credentials"),
                        new KeyValuePair<string,string>("scope",    "all-apis"),
                        new KeyValuePair<string,string>("client_id",   cid  ),
                        new KeyValuePair<string,string>("client_secret", csec)       
                    });

                    var client = ctx.RequestServices
                                .GetRequiredService<IHttpClientFactory>()
                                .CreateClient();
                    
                    var resp = await client.PostAsync(tokenUrl, form);
                    resp.EnsureSuccessStatusCode();

                    var tk = await resp.Content.ReadFromJsonAsync<TokenResponseInitial>()
                                ?? throw new Exception("Failed to parse refresh response.");

                    ctx.Session.SetString("auth_access_token",  tk.AccessToken);
                    ctx.Session.SetString("auth_refresh_token", string.Empty);
                    ctx.Session.SetString("auth_expires_at",
                        DateTimeOffset.UtcNow
                            .AddSeconds(tk.ExpiresIn - 60)
                            .ToString("o"));


                    return Results.Redirect("/?type=m2m");

                }

                return Results.Redirect("/?type=unknown");
            });

            // ─── U2M callback ─────────────────────────────────
            app.MapGet("/callback", async (HttpContext ctx) =>
            {
                var code = ctx.Request.Query["code"].ToString();

                var cid  = ctx.Session.GetString("auth_client_id")!;
                var csec = ctx.Session.GetString("auth_client_secret")!;
                var ruri = ctx.Session.GetString("auth_redirect_uri")!;
                

                var form = new FormUrlEncodedContent(new[]
                {
                    new KeyValuePair<string,string>("grant_type",    "authorization_code"),
                    new KeyValuePair<string,string>("code",          code),
                    new KeyValuePair<string,string>("redirect_uri",  ruri),
                    new KeyValuePair<string,string>("client_id",     cid),
                    new KeyValuePair<string,string>("client_secret", csec),
                });

                var client = ctx.RequestServices
                                .GetRequiredService<IHttpClientFactory>()
                                .CreateClient();
                var resp = await client.PostAsync(tokenUrl, form);
                resp.EnsureSuccessStatusCode();

                var tk = await resp.Content
                                .ReadFromJsonAsync<TokenResponseInitial>()
                        ?? throw new Exception("Bad token response");

                ctx.Session.SetString("auth_access_token",  tk.AccessToken);
                ctx.Session.SetString("auth_refresh_token", tk.RefreshToken);
                ctx.Session.SetString("auth_expires_at",
                    DateTimeOffset.UtcNow
                        .AddSeconds(tk.ExpiresIn - 60)
                        .ToString("o"));

                return Results.Redirect("/?type=U2M");
            });           

            // Not recommended in production code, but useful for testing
            app.MapGet("/session-data", (HttpContext ctx) =>
            {
                var clientIdDefault     = ctx.Session.GetString("auth_client_id") ?? builder.Configuration["DATABRICKS_CLIENT_ID"]    !;
                var clientSecretDefault = ctx.Session.GetString("auth_client_secret") ?? builder.Configuration["DATABRICKS_CLIENT_SECRET"]!;
                var redirectUriDefault  = ctx.Session.GetString("auth_redirect_url") ?? builder.Configuration["DATABRICKS_REDIRECT_URI"]!;
                var patDefault  =  ctx.Session.GetString("auth_path") ?? builder.Configuration["DATABRICKS_PAT"]!;
                var authType = ctx.Session.GetString("auth_type") ?? builder.Configuration["DATABRICKS_AUTH_TYPE"]!;

                var hasAccessToken = ctx.Session.GetString("auth_access_token") != null;


                return Results.Json(new {
                    clientId     =clientIdDefault,
                    clientSecret = clientSecretDefault,
                    redirectUri  = redirectUriDefault,
                    pat = patDefault,
                    authType = authType,
                    hasAccessToken =hasAccessToken
                });
            });

            
            // ─── Serve Data ─────────────────────────────
            app.MapGet("/query", async (HttpContext ctx) =>
            {
                
                var token = await Program.GetRefreshToken(ctx, tokenUrl);

                if (string.IsNullOrEmpty(token))
                    return Results.Unauthorized();

                var repo = new DatabricksRepo(
                    ctx.RequestServices.GetRequiredService<IHttpClientFactory>(),
                    workspaceUrl,
                    warehouseId
                );
                var rows = await repo.QueryAsync(token,
                    "SELECT count(1), pickup_zip FROM samples.nyctaxi.trips GROUP BY pickup_zip LIMIT 10");
                return Results.Json(rows);
            });

            // ─── Serve index.html ─────────────────────────────
            app.MapGet("/", async () =>
            {
                var html = await File.ReadAllTextAsync(Path.Combine("wwwroot", "index.html"));
                return Results.Content(html, "text/html");
            });

            app.Run();
        }
    }
}