namespace KQLAnalyzer
{
    /// <summary>
    /// Loads the table to event column mapping used to derive event filters
    /// (for example DeviceProcessEvents + ActionType, so that a predicate like
    /// ActionType == "ProcessCreated" becomes the event "ActionType:ProcessCreated").
    ///
    /// The mapping file is a simple CSV with one mapping per line:
    ///   Table,EventColumn
    /// A table may appear on multiple lines to map several event columns.
    /// Lines starting with # and the header line are ignored. Matching is
    /// case-insensitive; the casing from the file is kept as canonical output.
    /// </summary>
    public static class EventColumnMapping
    {
        public static IReadOnlyDictionary<string, IReadOnlyList<string>> Load(FileInfo file)
        {
            var mapping = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

            if (file != null && file.Exists)
            {
                foreach (var rawLine in File.ReadAllLines(file.FullName))
                {
                    var line = rawLine.Trim();
                    if (line.Length == 0 || line.StartsWith("#"))
                    {
                        continue;
                    }

                    var parts = line.Split(',');
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

                    // Skip the header line.
                    if (
                        table.Equals("Table", StringComparison.OrdinalIgnoreCase)
                        && column.Equals("EventColumn", StringComparison.OrdinalIgnoreCase)
                    )
                    {
                        continue;
                    }

                    if (!mapping.TryGetValue(table, out var columns))
                    {
                        columns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        mapping[table] = columns;
                    }

                    columns.Add(column);
                }
            }

            return mapping.ToDictionary(
                kvp => kvp.Key,
                kvp =>
                    (IReadOnlyList<string>)
                        kvp.Value.OrderBy(c => c, StringComparer.OrdinalIgnoreCase).ToList(),
                StringComparer.OrdinalIgnoreCase
            );
        }
    }
}
