namespace KQLAnalyzer;

/// <summary>
/// Loads the table-to-event-column mapping from a CSV file with the columns
/// "Table,EventColumn". Blank lines, lines starting with '#' and the header
/// row are ignored. Table and column names are matched case-insensitively;
/// the first spelling encountered is kept.
/// </summary>
public static class EventColumnMapping
{
    public static Dictionary<string, List<string>> Load(FileInfo? file)
    {
        var mapping = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        if (file == null || !file.Exists)
        {
            return mapping;
        }

        foreach (var line in File.ReadLines(file.FullName))
        {
            var trimmed = line.Trim();
            if (trimmed.Length == 0 || trimmed.StartsWith("#", StringComparison.Ordinal))
            {
                continue;
            }

            var parts = trimmed.Split(',');
            if (parts.Length < 2)
            {
                continue;
            }

            var table = parts[0].Trim();
            var column = parts[1].Trim();
            if (table.Length == 0 || column.Length == 0)
            {
                continue;
            }

            // Skip the header row.
            if (
                table.Equals("Table", StringComparison.OrdinalIgnoreCase)
                && column.Equals("EventColumn", StringComparison.OrdinalIgnoreCase)
            )
            {
                continue;
            }

            if (!mapping.TryGetValue(table, out var columns))
            {
                columns = new List<string>();
                mapping[table] = columns;
            }

            if (!columns.Contains(column, StringComparer.OrdinalIgnoreCase))
            {
                columns.Add(column);
            }
        }

        return mapping;
    }
}
