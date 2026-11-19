using Microsoft.AspNetCore.Identity;
using System.Collections.Concurrent;
using System.Text.Json;

namespace SdrGate;

public class ProxyStateStore
{
    private readonly string _filePath = Path.Combine(AppContext.BaseDirectory, "state.json");
    private readonly object _lock = new();
    private readonly PasswordHasher<string> _hasher = new();
    private StoredData _data;
    private readonly ConcurrentDictionary<string, ActiveSession> _active = new();
    private readonly ConcurrentDictionary<string, DateTime> _userOnlineSince = new(); // Время входа первого сокета
    private readonly ConcurrentDictionary<string, DateTime> _kickedUntil = new();

    public ProxyStateStore()
    {
        if (File.Exists(_filePath))
        {
            var json = File.ReadAllText(_filePath);
            _data = JsonSerializer.Deserialize<StoredData>(json) ?? new StoredData();
            MigratePlaintextPasswords();
        }
        else
        {
            _data = new StoredData();
            _data.Users["admin"] = _hasher.HashPassword("admin", "admin123");
            Save();
        }
    }
    private void MigratePlaintextPasswords()
    {
        bool changed = false;
        foreach (var kvp in _data.Users.ToList())
        {
            if (!kvp.Value.StartsWith("AQAAAA"))
            {
                _data.Users[kvp.Key] = _hasher.HashPassword(kvp.Key, kvp.Value);
                changed = true;
            }
        }
        if (changed) Save();
    }

    private void Save()
    {
        var json = JsonSerializer.Serialize(_data, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_filePath, json);
    }
    public bool ValidateUser(string username, string password)
    {
        string? storedHash;
        lock (_lock)
        {
            if (!_data.Users.TryGetValue(username, out storedHash))
                return false;
        }
        var res = _hasher.VerifyHashedPassword(username, storedHash, password);
        return res == PasswordVerificationResult.Success || res == PasswordVerificationResult.SuccessRehashNeeded;
    }
    public Dictionary<string, string> GetUsers()
    {
        lock (_lock) return new Dictionary<string, string>(_data.Users);
    }
    public Dictionary<string, double> GetUserStats()
    {
        lock (_lock) return new Dictionary<string, double>(_data.TotalListeningSeconds);
    }
    public void AddOrUpdateUser(string username, string password)
    {
        lock (_lock)
        {
            _data.Users[username] = _hasher.HashPassword(username, password);
            Save();
        }
    }
    public void DeleteUser(string username)
    {
        lock (_lock)
        {
            _data.Users.Remove(username);
            Save();
        }
    }
    public bool UserExists(string username)
    {
        lock (_lock) return _data.Users.ContainsKey(username);
    }

    public string StartSession(string username, string ip, CancellationTokenSource cts)
    {
        var id = Guid.NewGuid().ToString("N");
        var now = DateTime.UtcNow;

        lock (_lock)
        {
            // Если это первый активный сокет пользователя — фиксируем старт реального прослушивания
            if (!_active.Values.Any(s => s.Username == username))
            {
                _userOnlineSince[username] = now;
            }
            _active[id] = new ActiveSession(id, username, ip, now, cts);
        }

        return id;
    }

    public void EndSession(string id)
    {
        if (!_active.TryRemove(id, out var session)) return;

        var endUtc = DateTime.UtcNow;

        lock (_lock)
        {
            // Если у пользователя ещё остались другие открытые сокеты (из тех 5 штук) — время пока не фиксируем
            if (_active.Values.Any(s => s.Username == session.Username))
                return;

            // Закрылся последний сокет пользователя — берём реальное время старта первого сокета
            if (!_userOnlineSince.TryRemove(session.Username, out var realStartUtc))
                realStartUtc = session.StartedAt;

            var totalDuration = (endUtc - realStartUtc).TotalSeconds;
            if (totalDuration <= 1) return;

            // 1. Обновляем общее время за всё время
            _data.TotalListeningSeconds.TryGetValue(session.Username, out var currentTotal);
            _data.TotalListeningSeconds[session.Username] = currentTotal + totalDuration;

            // 2. Разбиваем реальный интервал по календарным дням
            var cursor = realStartUtc.ToLocalTime();
            var endLocal = endUtc.ToLocalTime();

            while (cursor < endLocal)
            {
                var nextMidnight = cursor.Date.AddDays(1);
                var sliceEnd = endLocal < nextMidnight ? endLocal : nextMidnight;
                var sliceSeconds = (sliceEnd - cursor).TotalSeconds;

                var dayKey = cursor.ToString("yyyy-MM-dd");
                if (!_data.DailyListeningSeconds.TryGetValue(dayKey, out var dayDict))
                {
                    dayDict = new Dictionary<string, double>();
                    _data.DailyListeningSeconds[dayKey] = dayDict;
                }

                dayDict.TryGetValue(session.Username, out var dayCurrent);
                dayDict[session.Username] = dayCurrent + sliceSeconds;

                cursor = sliceEnd;
            }

            // 3. Очищаем записи старше 60 дней
            var cutoffDay = DateTime.Now.Date.AddDays(-60).ToString("yyyy-MM-dd");
            foreach (var oldKey in _data.DailyListeningSeconds.Keys.Where(k => string.CompareOrdinal(k, cutoffDay) < 0).ToList())
            {
                _data.DailyListeningSeconds.Remove(oldKey);
            }

            Save();
        }
    }
    public void KickSession(string id, int cooldownSeconds = 15)
    {
        if (_active.TryGetValue(id, out var session))
        {
            _kickedUntil[session.Username] = DateTime.UtcNow.AddSeconds(cooldownSeconds);
            KickUserSessions(session.Username); // Разрываем все 5 сокетов этого пользователя сразу
        }
    }
    public void KickUserSessions(string username)
    {
        foreach (var session in _active.Values.Where(s => s.Username == username))
        {
            try { session.Cts.Cancel(); } catch { }
        }
    }
    public bool IsUserKicked(string username)
    {
        if (_kickedUntil.TryGetValue(username, out var until))
        {
            if (DateTime.UtcNow < until) return true;
            _kickedUntil.TryRemove(username, out _);
        }
        return false;
    }
    public List<ActiveSession> GetActiveSessions() => _active.Values.OrderBy(s => s.StartedAt).ToList();
    public Dictionary<string, DateTime> GetActiveUsersStartTimes() => new(_userOnlineSince);
    public Dictionary<string, Dictionary<string, double>> GetDailyStatsWithActive()
    {
        var result = new Dictionary<string, Dictionary<string, double>>();

        lock (_lock)
        {
            foreach (var (day, users) in _data.DailyListeningSeconds)
                result[day] = new Dictionary<string, double>(users);
        }

        var nowLocal = DateTime.Now;
        foreach (var (username, startUtc) in _userOnlineSince)
        {
            var cursor = startUtc.ToLocalTime();
            while (cursor < nowLocal)
            {
                var nextMidnight = cursor.Date.AddDays(1);
                var sliceEnd = nowLocal < nextMidnight ? nowLocal : nextMidnight;
                var dayKey = cursor.ToString("yyyy-MM-dd");

                if (!result.TryGetValue(dayKey, out var dayDict))
                {
                    dayDict = new Dictionary<string, double>();
                    result[dayKey] = dayDict;
                }

                dayDict.TryGetValue(username, out var cur);
                dayDict[username] = cur + (sliceEnd - cursor).TotalSeconds;
                cursor = sliceEnd;
            }
        }

        var cutoffDay = DateTime.Now.Date.AddDays(-60).ToString("yyyy-MM-dd");

        return result
            .Where(kv => string.CompareOrdinal(kv.Key, cutoffDay) >= 0)
            .OrderByDescending(kv => kv.Key)
            .ToDictionary(kv => kv.Key, kv => kv.Value);
    }
}
