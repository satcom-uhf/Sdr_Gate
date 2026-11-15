namespace SdrGate
{
    public record ActiveSession(string Id, string Username, string Ip, DateTime StartedAt, CancellationTokenSource Cts);
}
