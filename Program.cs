using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using SdrGate;
using Microsoft.AspNetCore.HttpOverrides;
using System.Net;
using System.Security.Claims;
using System.Text.Json;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSingleton<ProxyStateStore>();

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/proxy-login";
        options.AccessDeniedPath = "/proxy-login";
        options.Cookie.Name = "OpenWebRxAuth";
        options.Cookie.HttpOnly = true;
        options.Cookie.SameSite = SameSiteMode.Lax;
        options.ExpireTimeSpan = TimeSpan.FromHours(12);
        options.Events = new CookieAuthenticationEvents
        {
            OnRedirectToLogin = ctx =>
            {
                var returnUrl = Uri.EscapeDataString(ctx.Request.Path + ctx.Request.QueryString);
                ctx.Response.Redirect($"/proxy-login?ReturnUrl={returnUrl}");
                return Task.CompletedTask;
            },
            OnRedirectToAccessDenied = ctx =>
            {
                ctx.Response.Redirect("/proxy-login");
                return Task.CompletedTask;
            },
            OnValidatePrincipal = context =>
            {
                var store = context.HttpContext.RequestServices.GetRequiredService<ProxyStateStore>();
                var username = context.Principal?.Identity?.Name;

                if (string.IsNullOrEmpty(username) || !store.UserExists(username))
                {
                    context.RejectPrincipal();
                    context.HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                }

                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy =>
        policy.RequireAuthenticatedUser()
              .RequireUserName("admin"));
});

builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));
builder.Services.Configure<ForwardedHeadersOptions>(options =>
{
    options.ForwardedHeaders = ForwardedHeaders.XForwardedFor
                             | ForwardedHeaders.XForwardedProto
                             | ForwardedHeaders.XForwardedHost;
    // Доверяем локальному reverse-proxy роутера Keenetic
    options.KnownIPNetworks.Clear();
    options.KnownProxies.Clear();
});
var app = builder.Build();
app.UseForwardedHeaders();
app.UseAuthentication();
app.UseAuthorization();
app.UseWebSockets();
app.MapGet("/proxy-api/online", (HttpContext ctx, ProxyStateStore store) =>
{
    var onlineUsers = store.GetActiveSessions()
        .Select(s => s.Username)
        .Distinct()
        .OrderBy(name => name)
        .ToList();

    var isAdmin = ctx.User.Identity?.Name == "admin";

    return Results.Json(new { users = onlineUsers, isAdmin });
}).RequireAuthorization();
// Middleware для отслеживания и принудительного разрыва WebSocket-сессий
app.Use(async (ctx, next) =>
{
    var isWs = ctx.WebSockets.IsWebSocketRequest
               || ctx.Request.Headers.Upgrade.ToString().Equals("websocket", StringComparison.OrdinalIgnoreCase)
               || ctx.Request.Path.StartsWithSegments("/ws");

    if (isWs && ctx.User.Identity?.IsAuthenticated == true)
    {
        var store = ctx.RequestServices.GetRequiredService<ProxyStateStore>();
        var username = ctx.User.Identity.Name ?? "unknown";
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

        // Если пользователя только что кикнули — отклоняем авто-реконнект OpenWebRx+
        if (store.IsUserKicked(username))
        {
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            return;
        }

        using var cts = new CancellationTokenSource();
        using var reg = cts.Token.Register(() => ctx.Abort());

        var sessionId = store.StartSession(username, ip, cts);

        try
        {
            await next();
        }
        catch (OperationCanceledException)
        {
        }
        finally
        {
            store.EndSession(sessionId);
        }
    }
    else
    {
        await next();
    }
});// Страница входа
app.MapGet("/proxy-login", (HttpContext ctx) =>
{
    var error = ctx.Request.Query.ContainsKey("error")
        ? "<p style='color:#ff5555;'>Неверный логин или пароль</p>"
        : "";

    return Results.Content($$"""
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Вход — OpenWebRx+</title>
        <style>
            body { font-family: system-ui, sans-serif; background: #121212; color: #eee; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            form { background: #1e1e1e; padding: 2rem; border-radius: 8px; width: 100%; max-width: 320px; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }
            input { width: 100%; padding: 10px; margin: 6px 0 16px; border: 1px solid #333; border-radius: 4px; background: #2a2a2a; color: #fff; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #0078d4; border: none; border-radius: 4px; color: white; font-weight: bold; cursor: pointer; }
            button:hover { background: #0063b1; }
        </style>
    </head>
    <body>
        <form method="post" action="/proxy-login">
            <h3 style="margin-top:0;">Доступ к приёмнику</h3>
            {{error}}
            <label>Логин</label>
            <input type="text" name="username" required autofocus />
            <label>Пароль</label>
            <input type="password" name="password" required />
            <button type="submit">Войти</button>
        </form>
    </body>
    </html>
    """, "text/html; charset=utf-8");
});

app.MapPost("/proxy-login", async (HttpContext ctx, ProxyStateStore store) =>
{
    var form = await ctx.Request.ReadFormAsync();
    var username = form["username"].ToString().Trim();
    var password = form["password"].ToString();

    if (store.ValidateUser(username, password))
    {
        var claims = new List<Claim> { new(ClaimTypes.Name, username) };
        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
        await ctx.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(identity));
        return Results.Redirect("/");
    }

    return Results.Redirect("/proxy-login?error=1");
});

app.MapGet("/proxy-logout", async (HttpContext ctx) =>
{
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/proxy-login");
});

app.MapGet("/change-password", (HttpContext ctx) =>
{
    var username = ctx.User.Identity?.Name ?? "";
    var error = ctx.Request.Query.ContainsKey("error")
        ? "<p style='color:#ff5555;'>Текущий пароль неверен или пароли не совпадают</p>"
        : "";
    var backLink = username == "admin" ? "/admin" : "/";

    return Results.Content($$"""
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Смена пароля</title>
        <style>
            body { font-family: system-ui, sans-serif; background: #121212; color: #eee; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
            form { background: #1e1e1e; padding: 2rem; border-radius: 8px; width: 100%; max-width: 340px; }
            input { width: 100%; padding: 10px; margin: 6px 0 14px; border: 1px solid #333; border-radius: 4px; background: #2a2a2a; color: #fff; box-sizing: border-box; }
            button { width: 100%; padding: 10px; background: #0078d4; border: none; border-radius: 4px; color: white; font-weight: bold; cursor: pointer; }
            a { display: block; text-align: center; margin-top: 14px; color: #64b5f6; text-decoration: none; }
        </style>
    </head>
    <body>
        <form method="post" action="/change-password">
            <h3 style="margin-top:0;">Смена пароля ({{WebUtility.HtmlEncode(username)}})</h3>
            {{error}}
            <label>Текущий пароль</label>
            <input type="password" name="oldPassword" required autofocus />
            <label>Новый пароль</label>
            <input type="password" name="newPassword" required />
            <label>Повторите новый пароль</label>
            <input type="password" name="confirmPassword" required />
            <button type="submit">Сохранить</button>
            <a href="{{backLink}}">← Отмена</a>
        </form>
    </body>
    </html>
    """, "text/html; charset=utf-8");
}).RequireAuthorization();

// Обработка смены пароля
app.MapPost("/change-password", async (HttpContext ctx, ProxyStateStore store) =>
{
    var username = ctx.User.Identity?.Name;
    if (string.IsNullOrEmpty(username)) return Results.Unauthorized();

    var form = await ctx.Request.ReadFormAsync();
    var oldPwd = form["oldPassword"].ToString();
    var newPwd = form["newPassword"].ToString();
    var confirmPwd = form["confirmPassword"].ToString();

    if (string.IsNullOrWhiteSpace(newPwd) || newPwd != confirmPwd || !store.ValidateUser(username, oldPwd))
        return Results.Redirect("/change-password?error=1");

    store.AddOrUpdateUser(username, newPwd);
    store.KickUserSessions(username);
    await ctx.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);

    return Results.Redirect("/proxy-login");
}).RequireAuthorization();
// Панель администратора
app.MapGet("/admin", (HttpContext ctx, ProxyStateStore store) =>
{
    if (ctx.User.Identity?.Name != "admin") return Results.Forbid();

    var activeSessions = store.GetActiveSessions();
    var stats = store.GetUserStats();
    var users = store.GetUsers();
    var dailyStats = store.GetDailyStatsWithActive();
    var dailyRows = dailyStats.Count == 0
        ? "<tr><td colspan='3' style='color:#888;'>Записей по дням пока нет</td></tr>"
        : string.Join("", dailyStats.SelectMany(day =>
            day.Value
               .OrderByDescending(u => u.Value)
               .Select((u, idx) =>
               {
                   var dateCell = idx == 0 ? $"<b>{WebUtility.HtmlEncode(day.Key)}</b>" : "";
                   return $"<tr><td>{dateCell}</td><td>{WebUtility.HtmlEncode(u.Key)}</td><td>{FormatDuration(TimeSpan.FromSeconds(u.Value))}</td></tr>";
               })));
    string FormatDuration(TimeSpan ts) => ts.TotalHours >= 1
        ? $"{(int)ts.TotalHours} ч {ts.Minutes} мин {ts.Seconds} сек"
        : $"{ts.Minutes} мин {ts.Seconds} сек";

    var activeRows = activeSessions.Count == 0
        ? "<tr><td colspan='5' style='color:#888;'>Сейчас никто не слушает</td></tr>"
        : string.Join("", activeSessions.Select(s =>
            $"""
            <tr>
                <td><b>{WebUtility.HtmlEncode(s.Username)}</b></td>
                <td>{WebUtility.HtmlEncode(s.Ip)}</td>
                <td>{s.StartedAt.ToLocalTime():HH:mm:ss}</td>
                <td>{FormatDuration(DateTime.UtcNow - s.StartedAt)}</td>
                <td>
                    <form method='post' action='/admin/sessions/kick' style='margin:0;'>
                        <input type='hidden' name='sessionId' value='{WebUtility.HtmlEncode(s.Id)}'/>
                        <button type='submit' class='btn-kick'>Отключить</button>
                    </form>
                </td>
            </tr>
            """));

    var userRows = string.Join("", users.Select(u =>
    {
        var totalSec = stats.GetValueOrDefault(u.Key, 0);
        var activeSec = activeSessions.Where(s => s.Username == u.Key).Sum(s => (DateTime.UtcNow - s.StartedAt).TotalSeconds);
        var totalFormatted = FormatDuration(TimeSpan.FromSeconds(totalSec + activeSec));

        var deleteBtn = u.Key == "admin"
            ? "<span style='color:#666;'>нельзя удалить</span>"
            : $"<form method='post' action='/admin/users/delete' style='margin:0;'><input type='hidden' name='username' value='{WebUtility.HtmlEncode(u.Key)}'/><button type='submit' class='btn-del'>Удалить</button></form>";

        return $"<tr><td><b>{WebUtility.HtmlEncode(u.Key)}</b></td><td>{totalFormatted}</td><td>{deleteBtn}</td></tr>";
    }));

    return Results.Content($$"""
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Админка — OpenWebRx+ Proxy</title>
        <style>
            body { font-family: system-ui, sans-serif; background: #121212; color: #e0e0e0; max-width: 860px; margin: 2rem auto; padding: 0 1rem; }
            .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
            .card { background: #1e1e1e; border-radius: 8px; padding: 1.25rem; margin-bottom: 1.5rem; box-shadow: 0 2px 8px rgba(0,0,0,0.4); }
            h2 { margin-top: 0; font-size: 1.15rem; color: #64b5f6; }
            table { width: 100%; border-collapse: collapse; margin-top: 0.5rem; }
            th, td { text-align: left; padding: 10px; border-bottom: 1px solid #2c2c2c; }
            th { color: #999; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
            .add-form { display: flex; gap: 10px; margin-top: 1rem; }
            input { padding: 8px 12px; border: 1px solid #333; border-radius: 4px; background: #2a2a2a; color: #fff; flex: 1; }
            button { padding: 8px 16px; background: #0078d4; border: none; border-radius: 4px; color: #fff; font-weight: bold; cursor: pointer; }
            button:hover { background: #0063b1; }
            .btn-del, .btn-kick { background: #c62828; padding: 5px 10px; font-size: 0.85rem; }
            .btn-del:hover, .btn-kick:hover { background: #b71c1c; }
            .btn-kick { background: #e65100; }
            .btn-kick:hover { background: #bf360c; }
            a { color: #64b5f6; text-decoration: none; margin-left: 15px; }
        </style>
    </head>
    <body>
        <div class="header">
            <h1 style="margin:0; font-size:1.5rem;">Панель управления приёмником</h1>
            <div>
                <a href="/change-password">Сменить мой пароль</a>
                <a href="/">← К приёмнику</a>
                <a href="/settings">← Настройки приемника</a>
                <a href="/admin">Обновить</a>
                <a href="/proxy-logout" style="color:#ff7777;">Выйти</a>
            </div>
        </div>

        <div class="card">
            <h2>Сейчас в эфире (активные WebSocket-сессии)</h2>
            <table>
                <thead><tr><th>Пользователь</th><th>IP-адрес</th><th>Подключился</th><th>Длительность</th><th>Действие</th></tr></thead>
                <tbody>{{activeRows}}</tbody>
            </table>
        </div>

        <div class="card">
            <h2>Пользователи и общее время прослушивания</h2>
            <table>
                <thead><tr><th>Логин</th><th>Всего слушал</th><th>Действие</th></tr></thead>
                <tbody>{{userRows}}</tbody>
            </table>

            <form method="post" action="/admin/users/add" class="add-form">
                <input type="text" name="username" placeholder="Новый логин" required />
                <input type="password" name="password" placeholder="Пароль" required />
                <button type="submit">Добавить пользователя</button>
            </form>
        </div>
     <div class="card">
        <h2>Статистика по дням</h2>
        <table>
            <thead><tr><th>Дата</th><th>Пользователь</th><th>Время в эфире</th></tr></thead>
            <tbody>{{dailyRows}}</tbody>
        </table>
    </div>
    </body>
    </html>
    """, "text/html; charset=utf-8");
}).RequireAuthorization();

// Принудительный разрыв WebSocket-сессии
app.MapPost("/admin/sessions/kick", async (HttpContext ctx, ProxyStateStore store) =>
{
if (ctx.User.Identity?.Name != "admin") return Results.Forbid();
    var form = await ctx.Request.ReadFormAsync();
    var sessionId = form["sessionId"].ToString();
    store.KickSession(sessionId);
    // Небольшая пауза, чтобы блок finally успел удалить сессию из словаря до редиректа
    await Task.Delay(100);
    return Results.Redirect("/admin");
}).RequireAuthorization();
app.MapPost("/admin/users/add", async (HttpContext ctx, ProxyStateStore store) =>
{
    if (ctx.User.Identity?.Name != "admin") return Results.Forbid();
    var form = await ctx.Request.ReadFormAsync();
    var username = form["username"].ToString().Trim();
    var password = form["password"].ToString();
    if (!string.IsNullOrEmpty(username) && !string.IsNullOrEmpty(password))
    {
        store.AddOrUpdateUser(username, password);
    }
    return Results.Redirect("/admin");
}).RequireAuthorization();
// Удаление пользователя + разрыв всех его текущих сессий
app.MapPost("/admin/users/delete", async (HttpContext ctx, ProxyStateStore store) =>
{
    if (ctx.User.Identity?.Name != "admin") return Results.Forbid();
    var form = await ctx.Request.ReadFormAsync();
    var username = form["username"].ToString();
    if (username != "admin")
    {
        store.DeleteUser(username);
        store.KickUserSessions(username);
    }
    return Results.Redirect("/admin");
}).RequireAuthorization();
app.MapReverseProxy();
app.Run();