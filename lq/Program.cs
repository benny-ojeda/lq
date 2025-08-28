using System.DirectoryServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace lq
{
    public class LdapService
    {
        private readonly string _server;
        private readonly string? _username;
        private readonly string? _password;
        private readonly int? _port;

        public LdapService(string server, string? username = null, string? password = null, int? port = null)
        {
            _server = server;
            _username = username;
            _password = password;
            _port = port;
        }

        public List<Dictionary<string, object>> Search(string ldapFilter, string[]? propertiesToLoad = null)
        {
            // Use GC protocol for Global Catalog port (3268), otherwise use LDAP
            string protocol = (_port == 3268) ? "GC" : "LDAP";
            string portPart = _port.HasValue ? $":{_port}" : "";
            string ldapPath = $"{protocol}://{_server}{portPart}";

            var results = new List<Dictionary<string, object>>();

            try
            {
                using DirectoryEntry entry = _username != null
                    ? new DirectoryEntry(ldapPath, _username, _password)
                    : new DirectoryEntry(ldapPath);

                using DirectorySearcher searcher = new DirectorySearcher(entry)
                {
                    Filter = ldapFilter,
                    PageSize = 1000
                };

                if (propertiesToLoad != null)
                {
                    foreach (var prop in propertiesToLoad)
                        searcher.PropertiesToLoad.Add(prop);
                }

                foreach (SearchResult result in searcher.FindAll())
                {
                    var entryData = new Dictionary<string, object>();
                    foreach (string propName in result.Properties.PropertyNames)
                    {
                        if (propName.Equals("adspath", StringComparison.OrdinalIgnoreCase))
                            continue;

                        var propValues = result.Properties[propName];
                        var values = new List<string>();
                        foreach (var val in propValues)
                        {
                            if (val is byte[] bytes)
                            {
                                if (propName.Equals("objectguid", StringComparison.OrdinalIgnoreCase) && bytes.Length == 16)
                                {
                                    values.Add(new Guid(bytes).ToString());
                                }
                                else if (propName.Equals("objectsid", StringComparison.OrdinalIgnoreCase))
                                {
                                    try
                                    {
                                        values.Add(new SecurityIdentifier(bytes, 0).ToString());
                                    }
                                    catch
                                    {
                                        values.Add(ByteArrayToHex(bytes));
                                    }
                                }
                                else
                                {
                                    values.Add(ByteArrayToHex(bytes));
                                }
                            }
                            else if (val is long fileTimeValue1)
                            {
                                if (IsWindowsFileTimeAttribute(propName))
                                {
                                    values.Add(FileTimeToDateTimeString(fileTimeValue1));
                                }
                                else
                                {
                                    values.Add(fileTimeValue1.ToString());
                                }
                            }
                            else if (val is IConvertible convertible && convertible.GetTypeCode() == TypeCode.Int64)
                            {
                                long fileTimeValue2 = convertible.ToInt64(null);
                                if (IsWindowsFileTimeAttribute(propName))
                                {
                                    values.Add(FileTimeToDateTimeString(fileTimeValue2));
                                }
                                else
                                {
                                    values.Add(fileTimeValue2.ToString());
                                }
                            }
                            else
                            {
                                values.Add(val.ToString()!);
                            }
                        }

                        entryData[propName] = values.Count == 1 ? values[0] : values;
                    }
                    results.Add(entryData);
                }
            }
            catch (System.Runtime.InteropServices.COMException ex)
            {
                Console.Error.WriteLine($"Failed to connect to server '{_server}'. Please check the server and try again.");
                Console.Error.WriteLine($"Error: {ex.Message}");
                throw;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Unexpected error during LDAP search for server '{_server}': {ex.Message}");
                throw;
            }

            return results;
        }

        public List<Dictionary<string, object>> SearchByDistinguishedName(string distinguishedName, string[]? propertiesToLoad = null)
        {
            // Try multiple approaches to find the object by DN
            
            // First, try using the DN as a base path for search (more reliable)
            try
            {
                return SearchByDistinguishedNameDirect(distinguishedName, propertiesToLoad);
            }
            catch
            {
                // If direct approach fails, fall back to filter search
                try
                {
                    string filter = $"(distinguishedName={EscapeLdapFilter(distinguishedName)})";
                    return Search(filter, propertiesToLoad);
                }
                catch
                {
                    // Last resort: parse the DN and search with components
                    return SearchByDistinguishedNameFallback(distinguishedName, propertiesToLoad);
                }
            }
        }

        private List<Dictionary<string, object>> SearchByDistinguishedNameDirect(string distinguishedName, string[]? propertiesToLoad = null)
        {
            // Use GC protocol for Global Catalog port (3268), otherwise use LDAP
            string protocol = (_port == 3268) ? "GC" : "LDAP";
            string portPart = _port.HasValue ? $":{_port}" : "";
            
            // Parse the DN to extract the domain components for the base path
            string baseDn = ExtractBaseDnFromDn(distinguishedName);
            string ldapPath = $"{protocol}://{_server}{portPart}/{baseDn}";
            
            var results = new List<Dictionary<string, object>>();

            try
            {
                using DirectoryEntry entry = _username != null
                    ? new DirectoryEntry(ldapPath, _username, _password)
                    : new DirectoryEntry(ldapPath);

                using DirectorySearcher searcher = new DirectorySearcher(entry)
                {
                    Filter = $"(distinguishedName={EscapeLdapFilter(distinguishedName)})",
                    SearchScope = SearchScope.Subtree,
                    PageSize = 1000
                };

                if (propertiesToLoad != null)
                {
                    foreach (var prop in propertiesToLoad)
                        searcher.PropertiesToLoad.Add(prop);
                }

                foreach (SearchResult result in searcher.FindAll())
                {
                    var entryData = new Dictionary<string, object>();
                    foreach (string propName in result.Properties.PropertyNames)
                    {
                        if (propName.Equals("adspath", StringComparison.OrdinalIgnoreCase))
                            continue;

                        var propValues = result.Properties[propName];
                        var values = new List<string>();
                        foreach (var val in propValues)
                        {
                            if (val is byte[] bytes)
                            {
                                if (propName.Equals("objectguid", StringComparison.OrdinalIgnoreCase) && bytes.Length == 16)
                                {
                                    values.Add(new Guid(bytes).ToString());
                                }
                                else if (propName.Equals("objectsid", StringComparison.OrdinalIgnoreCase))
                                {
                                    try
                                    {
                                        values.Add(new SecurityIdentifier(bytes, 0).ToString());
                                    }
                                    catch
                                    {
                                        values.Add(ByteArrayToHex(bytes));
                                    }
                                }
                                else
                                {
                                    values.Add(ByteArrayToHex(bytes));
                                }
                            }
                            else if (val is long fileTimeValue1)
                            {
                                if (IsWindowsFileTimeAttribute(propName))
                                {
                                    values.Add(FileTimeToDateTimeString(fileTimeValue1));
                                }
                                else
                                {
                                    values.Add(fileTimeValue1.ToString());
                                }
                            }
                            else if (val is IConvertible convertible && convertible.GetTypeCode() == TypeCode.Int64)
                            {
                                long fileTimeValue2 = convertible.ToInt64(null);
                                if (IsWindowsFileTimeAttribute(propName))
                                {
                                    values.Add(FileTimeToDateTimeString(fileTimeValue2));
                                }
                                else
                                {
                                    values.Add(fileTimeValue2.ToString());
                                }
                            }
                            else
                            {
                                values.Add(val.ToString()!);
                            }
                        }

                        entryData[propName] = values.Count == 1 ? values[0] : values;
                    }
                    results.Add(entryData);
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"Direct DN search failed: {ex.Message}");
                throw;
            }

            return results;
        }

        private List<Dictionary<string, object>> SearchByDistinguishedNameFallback(string distinguishedName, string[]? propertiesToLoad = null)
        {
            // Parse the DN to extract CN or other identifying attributes
            var dnComponents = ParseDistinguishedName(distinguishedName);
            
            // Try to find by CN first
            if (dnComponents.TryGetValue("CN", out var cn))
            {
                string filter = $"(cn={EscapeLdapFilter(cn)})";
                var results = Search(filter, propertiesToLoad);
                
                // Filter results to match the exact DN
                return results.Where(r => 
                    r.TryGetValue("distinguishedname", out var dn) && 
                    string.Equals(dn.ToString(), distinguishedName, StringComparison.OrdinalIgnoreCase)
                ).ToList();
            }
            
            // If no CN, try other attributes
            foreach (var component in dnComponents)
            {
                if (component.Key != "DC" && component.Key != "OU")
                {
                    string filter = $"({component.Key.ToLower()}={EscapeLdapFilter(component.Value)})";
                    var results = Search(filter, propertiesToLoad);
                    
                    // Filter results to match the exact DN
                    var filtered = results.Where(r => 
                        r.TryGetValue("distinguishedname", out var dn) && 
                        string.Equals(dn.ToString(), distinguishedName, StringComparison.OrdinalIgnoreCase)
                    ).ToList();
                    
                    if (filtered.Count > 0)
                        return filtered;
                }
            }
            
            return new List<Dictionary<string, object>>();
        }

        private static string ExtractBaseDnFromDn(string distinguishedName)
        {
            // Extract DC components from DN to create base path
            var parts = distinguishedName.Split(',').Select(p => p.Trim());
            var dcParts = parts.Where(p => p.StartsWith("DC=", StringComparison.OrdinalIgnoreCase));
            
            if (dcParts.Any())
            {
                return string.Join(",", dcParts);
            }
            
            // If no DC parts found, return the full DN (might be a configuration container)
            return distinguishedName;
        }

        private static Dictionary<string, string> ParseDistinguishedName(string distinguishedName)
        {
            var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var parts = distinguishedName.Split(',').Select(p => p.Trim());
            
            foreach (var part in parts)
            {
                var equalIndex = part.IndexOf('=');
                if (equalIndex > 0 && equalIndex < part.Length - 1)
                {
                    var key = part.Substring(0, equalIndex).Trim();
                    var value = part.Substring(equalIndex + 1).Trim();
                    
                    // Only keep the first occurrence of each attribute type
                    if (!result.ContainsKey(key))
                    {
                        result[key] = value;
                    }
                }
            }
            
            return result;
        }

        private static string EscapeLdapFilter(string input)
        {
            // Escape special characters in LDAP filter values
            return input
                .Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00");
        }

        private static string ByteArrayToHex(byte[] bytes)
        {
            var sb = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
                sb.Append(b.ToString("X2"));
            return sb.ToString();
        }

        private static bool IsWindowsFileTimeAttribute(string propName)
        {
            return propName.Equals("lastlogon", StringComparison.OrdinalIgnoreCase)
                || propName.Equals("lastlogontimestamp", StringComparison.OrdinalIgnoreCase)
                || propName.Equals("pwdlastset", StringComparison.OrdinalIgnoreCase)
                || propName.Equals("accountexpires", StringComparison.OrdinalIgnoreCase)
                || propName.Equals("badpasswordtime", StringComparison.OrdinalIgnoreCase)
                || propName.Equals("lastlogoff", StringComparison.OrdinalIgnoreCase)
                || propName.Equals("lockouttime", StringComparison.OrdinalIgnoreCase)
                || propName.Equals("whencreated", StringComparison.OrdinalIgnoreCase)
                || propName.Equals("whenchanged", StringComparison.OrdinalIgnoreCase);
        }

        private static string FileTimeToDateTimeString(long fileTime)
        {
            if (fileTime == 0 || fileTime == long.MaxValue)
                return "Never";
            try
            {
                var dt = DateTimeOffset.FromFileTime(fileTime).ToLocalTime();
                // Use default ISO 8601 format (sortable, e.g., 2024-04-27T15:30:00+03:00)
                return dt.ToString("O"); // "O" is the round-trip (ISO 8601) format
            }
            catch
            {
                return fileTime.ToString();
            }
        }
    }

    class Program
    {
        private const string ToolDescription = "LDAP Query Console Utility for Active Directory";
        private const string ToolCopyright = "Copyright (c) 2024";
        private static readonly string ToolVersion =
            typeof(Program).Assembly.GetName().Version?.ToString() ?? "unknown";

        // Dynamic executable name
        private static string ExecutableName =>
            System.IO.Path.GetFileName(Environment.GetCommandLineArgs()[0]);

        static void PrintUsage()
        {
            string exe = ExecutableName;
            string[] lines = new[]
            {
                $"{exe,-10} - {ToolDescription}",
                "",
                "USAGE:",
                $"  {exe} [options] [samAccountName|DN|SID|email|inputFile] [properties]",
                "",
                "OPTIONS:",
                "  -s, --server <server>[:port]    Specify the domain controller or GC host",
                "  -f, --filter <ldapFilter>       LDAP filter (RFC 4515)",
                "  -dn, --distinguishedname <dn>   Search by Distinguished Name",
                "  -sid, --sid <sid>               Search by SID (e.g., S-1-5-21-...)",
                "  -e, --email <email>             Search by email (mail attribute)",
                "  -i, --input <file>              File with samAccountName, DN, SID, or email (one per line)",
                "                                  (You can also pass the file as the first positional argument)",
                "  -p, --properties <props>        Comma-separated list of properties",
                "  -o, --output <fmt>              Output format: json, csv",
                "  -u, --username <user>           Username for authentication",
                "  -pw, --password <pass>          Password for authentication",
                "  -h, --help                      Show this help message and exit",
                "  -v, --version                   Show version information and exit",
                "",
                "ARGUMENTS:",
                "  samAccountName|DN|SID|email|file If no filter or DN is specified, the first argument",
                "                                    is treated as samAccountName, Distinguished Name, SID,",
                "                                    email, or as an input file path",
                "  properties                       Comma-separated list of properties to retrieve",
                "                                    (alternative to -p switch)",
                "",
                "EXAMPLES:",
                $"  {exe} -s dc01 -f \"(objectClass=user)\"",
                $"  {exe} -dn \"CN=John Doe,OU=Users,DC=contoso,DC=com\"",
                $"  {exe} \"CN=John Doe,OU=Users,DC=contoso,DC=com\" -p cn,mail",
                $"  {exe} jdoe",
                $"  {exe} jdoe cn,mail",
                $"  {exe} -sid S-1-5-21-123-456-789-1001",
                $"  {exe} -e john.doe@contoso.com",
                $"  {exe} -s dc01 -f \"(samaccountname=jdoe)\" -p cn,mail -o json",
                $"  {exe} -s dc01:3268 -f \"(objectClass=computer)\" -o csv",
                $"  {exe} -i ids.txt -p cn,mail -o json",
                $"  {exe} ids.txt -p cn,mail -o json"
            };

            int maxLen = lines.Max(l => l.Length);
            int boxWidth = maxLen + 2; // 2 spaces padding

            string top = "╔" + new string('═', boxWidth) + "╗";
            string sep = "╠" + new string('═', boxWidth) + "╣";
            string mid = "╠" + new string('═', boxWidth) + "╣";
            string bottom = "╚" + new string('═', boxWidth) + "╝";

            Console.WriteLine();
            Console.WriteLine(top);
            Console.WriteLine($"║ {lines[0].PadRight(boxWidth - 1)}║");
            Console.WriteLine(sep);

            for (int i = 1; i < lines.Length; i++)
            {
                if (lines[i] == "EXAMPLES:")
                {
                    Console.WriteLine(mid);
                }
                Console.WriteLine($"║ {lines[i].PadRight(boxWidth - 1)}║");
            }
            Console.WriteLine(bottom);
            Console.WriteLine();
        }

        static void PrintVersion()
        {
            Console.WriteLine($"{ExecutableName} version {ToolVersion}");
            Console.WriteLine($"{ToolDescription}");
            Console.WriteLine($"{ToolCopyright}");
        }

        static bool IsValidSamAccountName(string sam)
        {
            // 1-20 chars, alphanumeric, dot, dash, underscore, dollar sign
            return Regex.IsMatch(sam, @"^[\w.\-$]{1,20}$");
        }

        private static bool IsLikelyDistinguishedName(string line)
        {
            if (string.IsNullOrWhiteSpace(line)) return false;
            // Very lightweight DN heuristic: contains '=' and at least one RDN like CN/OU and a DC component
            if (!line.Contains('=')) return false;
            var upper = line.ToUpperInvariant();
            return (upper.Contains("CN=") || upper.Contains("OU=") || upper.Contains("CN =") || upper.Contains("OU =") || upper.Contains("DC="));
        }

        private static bool IsValidSid(string s)
        {
            // Basic SID validation: S-1-... with digits and dashes
            return Regex.IsMatch(s, @"^S-\d(-\d+){1,}$", RegexOptions.IgnoreCase);
        }

        private static bool IsValidEmail(string s)
        {
            // Simple email validation sufficient for CLI routing
            return Regex.IsMatch(s, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        }

        private static string EscapeLdapFilter(string input)
        {
            // Escape special characters in LDAP filter values
            return input
                .Replace("\\", "\\5c")
                .Replace("*", "\\2a")
                .Replace("(", "\\28")
                .Replace(")", "\\29")
                .Replace("\0", "\\00");
        }

        private static string BuildSidFilterTerm(string sid)
        {
            // Build LDAP filter term for objectSid using binary escaped bytes (RFC 4515)
            try
            {
                var sidObj = new SecurityIdentifier(sid);
                var bytes = new byte[sidObj.BinaryLength];
                sidObj.GetBinaryForm(bytes, 0);
                var sb = new StringBuilder(bytes.Length * 3);
                foreach (var b in bytes)
                {
                    sb.Append('\\');
                    sb.Append(b.ToString("X2"));
                }
                return $"objectSid={sb}";
            }
            catch
            {
                // Fallback use string form (AD typically accepts this as well)
                return $"objectSid={EscapeLdapFilter(sid)}";
            }
        }

        private static string BuildEmailFilterTerm(string email)
        {
            return $"mail={EscapeLdapFilter(email)}";
        }

        static Dictionary<string, string?> ParseArgs(string[] args)
        {
            var switchMap = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "s", "server" },
                { "server", "server" },
                { "f", "filter" },
                { "filter", "filter" },
                { "dn", "distinguishedname" },
                { "distinguishedname", "distinguishedname" },
                { "distinguished-name", "distinguishedname" },
                { "sid", "sid" },
                { "email", "email" },
                { "e", "email" },
                { "p", "properties" },
                { "properties", "properties" },
                { "o", "output" },
                { "output", "output" },
                { "u", "username" },
                { "username", "username" },
                { "pw", "password" },
                { "password", "password" },
                { "h", "help" },
                { "help", "help" },
                { "v", "version" },
                { "version", "version" },
                { "i", "input" },
                { "input", "input" }
            };

            var dict = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

            // If no arguments, show help and exit
            if (args.Length == 0)
            {
                PrintUsage();
                Environment.Exit(1);
            }

            string? positionalSam = null;
            string? positionalProperties = null;

            for (int i = 0; i < args.Length; i++)
            {
                if (args[i].StartsWith("--"))
                {
                    var key = args[i][2..];
                    string? value = null;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        value = args[i + 1];
                        i++;
                    }
                    if (switchMap.TryGetValue(key, out var mappedKey))
                    {
                        if (mappedKey == "help")
                        {
                            PrintUsage();
                            Environment.Exit(0);
                        }
                        if (mappedKey == "version")
                        {
                            PrintVersion();
                            Environment.Exit(0);
                        }
                        if ((mappedKey == "server" || mappedKey == "username" || mappedKey == "password" || mappedKey == "filter" || mappedKey == "distinguishedname" || mappedKey == "sid" || mappedKey == "email" || mappedKey == "properties" || mappedKey == "output" || mappedKey == "input")
                            && (value == null || value.Trim().Length == 0))
                        {
                            Console.Error.WriteLine($"Error: Option '--{key}' requires a value.");
                            PrintUsage();
                            Environment.Exit(1);
                        }
                        dict[mappedKey] = value ?? "true";
                    }
                    else
                    {
                        Console.Error.WriteLine($"Error: Unknown option '--{key}'");
                        PrintUsage();
                        Environment.Exit(1);
                    }
                }
                else if (args[i].StartsWith("-") && !args[i].StartsWith("--"))
                {
                    // Support single-dash options with one or more letters (e.g., -s, -f, -dn, -sid, -e)
                    var key = args[i][1..];
                    string? value = null;
                    if (i + 1 < args.Length && !args[i + 1].StartsWith("-"))
                    {
                        value = args[i + 1];
                        i++;
                    }

                    if (switchMap.TryGetValue(key, out var mappedKey))
                    {
                        if (mappedKey == "help")
                        {
                            PrintUsage();
                            Environment.Exit(0);
                        }
                        if (mappedKey == "version")
                        {
                            PrintVersion();
                            Environment.Exit(0);
                        }
                        if ((mappedKey == "server" || mappedKey == "username" || mappedKey == "password" || mappedKey == "filter" || mappedKey == "distinguishedname" || mappedKey == "sid" || mappedKey == "email" || mappedKey == "properties" || mappedKey == "output" || mappedKey == "input")
                            && (value == null || value.Trim().Length == 0))
                        {
                            Console.Error.WriteLine($"Error: Option '-{key}' requires a value.");
                            PrintUsage();
                            Environment.Exit(1);
                        }
                        dict[mappedKey] = value ?? "true";
                    }
                    else if (key.Length == 1 && switchMap.TryGetValue(key, out mappedKey))
                    {
                        // Single-letter short option (kept for completeness)
                        if (mappedKey == "help")
                        {
                            PrintUsage();
                            Environment.Exit(0);
                        }
                        if (mappedKey == "version")
                        {
                            PrintVersion();
                            Environment.Exit(0);
                        }
                        if ((mappedKey == "server" || mappedKey == "username" || mappedKey == "password" || mappedKey == "filter" || mappedKey == "distinguishedname" || mappedKey == "sid" || mappedKey == "email" || mappedKey == "properties" || mappedKey == "output" || mappedKey == "input")
                            && (value == null || value.Trim().Length == 0))
                        {
                            Console.Error.WriteLine($"Error: Option '-{key}' requires a value.");
                            PrintUsage();
                            Environment.Exit(1);
                        }
                        dict[mappedKey] = value ?? "true";
                    }
                    else
                    {
                        Console.Error.WriteLine($"Error: Unknown option '-{key}'");
                        PrintUsage();
                        Environment.Exit(1);
                    }
                }
                else
                {
                    // Handle positional arguments
                    // Treat first positional as input file if it exists; otherwise decide between target and properties
                    if (positionalSam == null)
                    {
                        // If the first positional is a file path, treat it as input file
                        if (!dict.ContainsKey("input") && File.Exists(args[i]))
                        {
                            dict["input"] = args[i];
                        }
                        else
                        {
                            // If a target is already specified via switches or input, treat this as properties
                            bool targetAlreadySpecified = dict.ContainsKey("filter")
                                || dict.ContainsKey("distinguishedname")
                                || dict.ContainsKey("input")
                                || dict.ContainsKey("dn-input")
                                || dict.ContainsKey("sid")
                                || dict.ContainsKey("email");
                            if (targetAlreadySpecified)
                            {
                                positionalProperties = args[i];
                            }
                            else
                            {
                                positionalSam = args[i];
                            }
                        }
                    }
                    else if (positionalProperties == null)
                    {
                        positionalProperties = args[i];
                    }
                    else
                    {
                        Console.Error.WriteLine($"Error: Unknown argument '{args[i]}'");
                        PrintUsage();
                        Environment.Exit(1);
                    }
                }
            }

            // Set properties from second positional argument if not already set via -p switch
            if (positionalProperties != null && !dict.ContainsKey("properties"))
            {
                dict["properties"] = positionalProperties;
            }

            // If explicit --sid/--email was provided and no filter was provided, convert to filter
            if (!dict.ContainsKey("filter"))
            {
                if (dict.TryGetValue("sid", out var sidValue) && !string.IsNullOrWhiteSpace(sidValue))
                {
                    dict["filter"] = $"({BuildSidFilterTerm(sidValue)})";
                    dict["sid-search"] = "true";
                }
                else if (dict.TryGetValue("email", out var emailValue) && !string.IsNullOrWhiteSpace(emailValue))
                {
                    dict["filter"] = $"({BuildEmailFilterTerm(emailValue)})";
                    dict["email-search"] = "true";
                }
            }

            // If no filter or DN is set, determine filter based on samfile or positionalSam
            if (!dict.ContainsKey("filter") && !dict.ContainsKey("distinguishedname"))
            {
                if (dict.TryGetValue("input", out var inputFile) && !string.IsNullOrWhiteSpace(inputFile))
                {
                    var lines = ReadNonEmptyLinesFromFile(inputFile);
                    if (lines.Count == 0)
                    {
                        Console.Error.WriteLine($"Error: No entries found in file '{inputFile}'.");
                        Environment.Exit(1);
                    }

                    if (lines.All(IsLikelyDistinguishedName))
                    {
                        // Mark as DN batch input
                        dict["dn-input"] = inputFile;
                    }
                    else if (lines.All(IsValidSamAccountName))
                    {
                        // Build an OR filter: (|(samaccountname=sam1)(samaccountname=sam2)...)
                        var filter = "(|" + string.Join("", lines.Select(s => $"(samaccountname={s})")) + ")";
                        dict["filter"] = filter;
                    }
                    else if (lines.All(IsValidSid))
                    {
                        // Build OR filter for SIDs using binary format
                        var filter = "(|" + string.Join("", lines.Select(s => $"({BuildSidFilterTerm(s)})")) + ")";
                        dict["filter"] = filter;
                        dict["sid-search"] = "true";
                    }
                    else if (lines.All(IsValidEmail))
                    {
                        // Build OR filter for emails (mail attr)
                        var filter = "(|" + string.Join("", lines.Select(s => $"({BuildEmailFilterTerm(s)})")) + ")";
                        dict["filter"] = filter;
                        dict["email-search"] = "true";
                    }
                    else
                    {
                        Console.Error.WriteLine($"Error: The file '{inputFile}' contains invalid or mixed entries. Use either all samAccountNames, all Distinguished Names, all SIDs, or all emails.");
                        Environment.Exit(1);
                    }
                }
                else if (positionalSam != null)
                {
                    if (IsLikelyDistinguishedName(positionalSam))
                    {
                        dict["distinguishedname"] = positionalSam;
                    }
                    else if (IsValidSamAccountName(positionalSam))
                    {
                        dict["filter"] = $"(samaccountname={positionalSam})";
                    }
                    else if (IsValidSid(positionalSam))
                    {
                        dict["filter"] = $"({BuildSidFilterTerm(positionalSam)})";
                        dict["sid-search"] = "true";
                    }
                    else if (IsValidEmail(positionalSam))
                    {
                        dict["filter"] = $"({BuildEmailFilterTerm(positionalSam)})";
                        dict["email-search"] = "true";
                    }
                    else
                    {
                        Console.Error.WriteLine("Error: The first argument is neither a valid samAccountName, Distinguished Name, SID, nor email.");
                        PrintUsage();
                        Environment.Exit(1);
                    }
                }
            }

            return dict;
        }

        static void PrintResults(List<Dictionary<string, object>> results, string format, string[]? propertiesToLoad = null)
        {
            // Treat -p * as "all properties" (default output)
            if (propertiesToLoad != null && propertiesToLoad.Length == 1 && propertiesToLoad[0] == "*")
            {
                propertiesToLoad = null;
            }

            // If only one property is requested and format is default, print only the value(s) for that property
            if (propertiesToLoad != null && propertiesToLoad.Length == 1 && format.ToLowerInvariant() == "default")
            {
                string prop = propertiesToLoad[0];
                bool colorize = Console.IsOutputRedirected == false;
                foreach (var entry in results)
                {
                    if (entry.TryGetValue(prop, out var value))
                    {
                        if (value is List<string> list)
                        {
                            foreach (var v in list)
                            {
                                WriteValueColored(v, colorize);
                                Console.WriteLine();
                            }
                        }
                        else
                        {
                            WriteValueColored(value, colorize);
                            Console.WriteLine();
                        }
                    }
                }
                return;
            }

            switch (format.ToLowerInvariant())
            {
                case "json":
                    Console.WriteLine(JsonSerializer.Serialize(results, new JsonSerializerOptions { WriteIndented = true }));
                    break;
                case "csv":
                    PrintCsv(results);
                    break;
                default:
                    PrintDefault(results);
                    break;
            }
        }

        static void PrintDefault(List<Dictionary<string, object>> results)
        {
            if (results.Count == 0)
            {
                Console.WriteLine("No results.");
                return;
            }
            bool colorize = Console.IsOutputRedirected == false;

            int maxPropLen = results
                .SelectMany(entry => entry.Keys)
                .DefaultIfEmpty("")
                .Max(k => k.Length);

            int valueStartCol = maxPropLen + 2; // 2 spaces after property name

            for (int i = 0; i < results.Count; i++)
            {
                var entry = results[i];
                foreach (var kvp in entry)
                {
                    string propName = kvp.Key;
                    string propLabel = propName.PadRight(maxPropLen);

                    if (kvp.Value is List<string> list)
                    {
                        if (list.Count == 1)
                        {
                            WriteColored($"{propLabel}: ", ConsoleColor.Cyan, colorize);
                            WriteValueColored(list[0], colorize);
                            Console.WriteLine();
                        }
                        else if (list.Count > 1)
                        {
                            WriteColored($"{propLabel}: ", ConsoleColor.Cyan, colorize);
                            WriteValueColored(list[0], colorize);
                            Console.WriteLine();
                            for (int j = 1; j < list.Count; j++)
                            {
                                Console.Write(new string(' ', valueStartCol));
                                WriteValueColored(list[j], colorize);
                                Console.WriteLine();
                            }
                        }
                    }
                    else
                    {
                        WriteColored($"{propLabel}: ", ConsoleColor.Cyan, colorize);
                        WriteValueColored(kvp.Value, colorize);
                        Console.WriteLine();
                    }
                }
            }
        }

        static void PrintCsv(List<Dictionary<string, object>> results)
        {
            if (results.Count == 0)
            {
                Console.WriteLine("No results.");
                return;
            }
            var allKeys = results.SelectMany(d => d.Keys).Distinct().ToList();
            Console.WriteLine(string.Join(",", allKeys.Select(EscapeCsv)));
            foreach (var entry in results)
            {
                Console.WriteLine(string.Join(",", allKeys.Select(k =>
                {
                    if (!entry.TryGetValue(k, out var v)) return "";
                    if (v is List<string> list) return EscapeCsv(string.Join(";", list));
                    return EscapeCsv(v?.ToString() ?? "");
                })));
            }
        }

        static string EscapeCsv(string s)
        {
            if (s.Contains('"') || s.Contains(',') || s.Contains('\n'))
                return $"\"{s.Replace("\"", "\"\"")}\"";
            return s;
        }

        static void WriteColored(string text, ConsoleColor color, bool colorize)
        {
            if (colorize)
            {
                var old = Console.ForegroundColor;
                Console.ForegroundColor = color;
                Console.Write(text);
                Console.ForegroundColor = old;
            }
            else
            {
                Console.Write(text);
            }
        }

        static void WriteValueColored(object? value, bool colorize)
        {
            if (value == null)
            {
                WriteColored("null", ConsoleColor.DarkGray, colorize);
                return;
            }
            string s = value.ToString() ?? "";
            if (DateTime.TryParse(s, out _))
            {
                WriteColored(s, ConsoleColor.Magenta, colorize);
            }
            else if (long.TryParse(s, out _))
            {
                WriteColored(s, ConsoleColor.Yellow, colorize);
            }
            else if (s.Equals("Never", StringComparison.OrdinalIgnoreCase))
            {
                WriteColored(s, ConsoleColor.DarkGray, colorize);
            }
            else
            {
                WriteColored(s, ConsoleColor.Green, colorize);
            }
        }

        static List<string> ReadSamAccountNamesFromFile(string filename)
        {
            var list = new List<string>();
            foreach (var line in File.ReadLines(filename))
            {
                var sam = line.Trim();
                if (string.IsNullOrEmpty(sam)) continue;
                if (!IsValidSamAccountName(sam))
                {
                    Console.Error.WriteLine($"Error: Invalid samAccountName '{sam}' in file '{filename}'.");
                    Environment.Exit(1);
                }
                list.Add(sam);
            }
            if (list.Count == 0)
            {
                Console.Error.WriteLine($"Error: No valid samAccountName entries found in file '{filename}'.");
                Environment.Exit(1);
            }
            return list;
        }

        static List<string> ReadNonEmptyLinesFromFile(string filename)
        {
            var list = new List<string>();
            foreach (var line in File.ReadLines(filename))
            {
                var s = line.Trim();
                if (!string.IsNullOrWhiteSpace(s)) list.Add(s);
            }
            return list;
        }

        static void Main(string[] args)
        {
            var argDict = ParseArgs(args);

            string? server = null;
            string? ldapFilter = null;
            string? distinguishedName = null;
            int? port = null;

            argDict.TryGetValue("server", out server);
            argDict.TryGetValue("filter", out ldapFilter);
            argDict.TryGetValue("distinguishedname", out distinguishedName);
            bool hasDnInput = argDict.TryGetValue("dn-input", out var dnInputFile) && !string.IsNullOrWhiteSpace(dnInputFile);

            // Track whether user explicitly set -s/--server
            bool serverSpecified = argDict.ContainsKey("server");

            // If server is not specified, use the current domain's DNS name
            if (string.IsNullOrWhiteSpace(server))
            {
                try
                {
                    var currentDomain = System.DirectoryServices.ActiveDirectory.Domain.GetCurrentDomain();
                    server = currentDomain.Name;
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Could not determine the default server (current domain). Please specify --server or -s.");
                    Console.Error.WriteLine($"Error: {ex.Message}");
                    PrintUsage();
                    Environment.Exit(1);
                }
            }

            // Check that either filter or DN is provided (or DN batch input)
            if (string.IsNullOrWhiteSpace(ldapFilter) && string.IsNullOrWhiteSpace(distinguishedName) && !hasDnInput)
            {
                Console.Error.WriteLine("Error: Either --filter|-f or --distinguishedname|-dn is required, or provide -i with a DN list.");
                PrintUsage();
                Environment.Exit(1);
            }

            // Check that both filter and DN are not provided at the same time
            if (!string.IsNullOrWhiteSpace(ldapFilter) && !string.IsNullOrWhiteSpace(distinguishedName))
            {
                Console.Error.WriteLine("Error: Cannot specify both --filter|-f and --distinguishedname|-dn at the same time.");
                PrintUsage();
                Environment.Exit(1);
            }

            string[]? propertiesToLoad = null;
            if (argDict.TryGetValue("properties", out var props) && !string.IsNullOrWhiteSpace(props))
            {
                propertiesToLoad = props.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            }

            string outputFormat = "default";
            if (argDict.TryGetValue("output", out var outFmt) && !string.IsNullOrWhiteSpace(outFmt))
                outputFormat = outFmt;

            string? username = null;
            string? password = null;

            if (argDict.TryGetValue("username", out var user) && !string.IsNullOrWhiteSpace(user))
                username = user;
            if (argDict.TryGetValue("password", out var pass) && !string.IsNullOrWhiteSpace(pass))
                password = pass;

            // Parse server for :port
            if (!string.IsNullOrWhiteSpace(server))
            {
                var (host, prt) = ParseHostAndPort(server);
                server = host;
                port = prt;
            }

            // Auto-use GC for SID/email searches when -s not specified
            bool sidSearch = argDict.ContainsKey("sid-search") || (!string.IsNullOrEmpty(ldapFilter) && ldapFilter.IndexOf("objectsid=", StringComparison.OrdinalIgnoreCase) >= 0);
            bool emailSearch = argDict.ContainsKey("email-search") || (!string.IsNullOrEmpty(ldapFilter) && ldapFilter.IndexOf("mail=", StringComparison.OrdinalIgnoreCase) >= 0);
            if (!serverSpecified && string.IsNullOrWhiteSpace(distinguishedName) && (sidSearch || emailSearch))
            {
                port = 3268; // GC
            }

            var ldapService = new LdapService(server!, username, password, port);

            try
            {
                List<Dictionary<string, object>> results;
                
                if (hasDnInput)
                {
                    var dns = ReadNonEmptyLinesFromFile(dnInputFile!);
                    var aggregated = new List<Dictionary<string, object>>();
                    foreach (var dn in dns)
                    {
                        try
                        {
                            var r = ldapService.SearchByDistinguishedName(dn, propertiesToLoad);
                            if (r.Count == 0)
                            {
                                Console.Error.WriteLine($"No results for DN: {dn}");
                            }
                            aggregated.AddRange(r);
                        }
                        catch (Exception ex)
                        {
                            Console.Error.WriteLine($"Failed to search DN '{dn}': {ex.Message}");
                        }
                    }
                    results = aggregated;
                }
                else if (!string.IsNullOrWhiteSpace(distinguishedName))
                {
                    results = ldapService.SearchByDistinguishedName(distinguishedName, propertiesToLoad);
                }
                else
                {
                    results = ldapService.Search(ldapFilter!, propertiesToLoad);
                }
                
                PrintResults(results, outputFormat, propertiesToLoad);
            }
            catch (Exception)
            {
                Environment.Exit(2);
            }
        }

        // Helper to parse host:port
        private static (string host, int? port) ParseHostAndPort(string input)
        {
            var idx = input.LastIndexOf(':');
            if (idx > 0 && idx < input.Length - 1 && int.TryParse(input[(idx + 1)..], out var port))
            {
                return (input[..idx], port);
            }
            return (input, null);
        }
    }
}