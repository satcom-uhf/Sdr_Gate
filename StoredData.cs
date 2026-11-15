namespace SdrGate
{
    class StoredData
    {
        public Dictionary<string, string> Users { get; set; } = new();
        public Dictionary<string, double> TotalListeningSeconds { get; set; } = new();
        // Новое поле: Дата ("yyyy-MM-dd") -> (Логин -> Секунды)
        public Dictionary<string, Dictionary<string, double>> DailyListeningSeconds { get; set; } = new();
    }
}
