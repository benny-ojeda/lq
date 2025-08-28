# lq – LDAP Query Console Utility for Active Directory

LDAP query console utility for Active Directory on .NET 8.

Features
- Query AD over LDAP or Global Catalog (GC)
- Search by LDAP filter, Distinguished Name (DN), SID, or email
- Batch input from file (samAccountName, DN, SID, or email)
- Select specific attributes to return; single-attribute mode prints values only
- Output formats: default (human-friendly), JSON, CSV
- Decodes common AD types (objectSid, objectGUID, FILETIME) for readability
- Auto-selects GC (port 3268) for SID/email searches when server not specified

Requirements
- Windows (uses System.DirectoryServices)
- .NET 8 SDK
- Network connectivity to a domain controller or GC

Install / Build
```bash
# Clone and build
 git clone https://github.com/benny-ojeda/lq
 cd lq

# Build
 dotnet build -c Release

# Run (from source)
 dotnet run --project lq -- -h

# Publish a single-file executable (win-x64)
 dotnet publish lq/lq.csproj -c Release -r win-x64 -p:PublishSingleFile=true --self-contained false
```
The published executable will be under lq/bin/Release/net8.0/...

Quick start
```bash
# Search by filter on the current domain
lq -f "(samaccountname=jdoe)"

# Search a GC (port 3268); useful for forest-wide lookups
lq -s dc01.contoso.com:3268 -f "(objectClass=user)" -o json

# Search by Distinguished Name (DN)
lq -dn "CN=John Doe,OU=Users,DC=contoso,DC=com" -p cn,mail

# Positional convenience: first arg -> samAccountName; second -> properties
lq jdoe cn,mail

# Search by SID or email (auto-uses GC when -s is omitted)
lq -sid S-1-5-21-123-456-789-1001
lq -e john.doe@contoso.com

# Bulk search from file (DN, samAccountName, SID, or email per line)
lq -i ids.txt -p cn,mail -o csv

# JSON output for computers
lq -s dc01 -f "(objectClass=computer)" -o json

# Counts
lq -f "(objectClass=user)" -c
lq -f "(objectClass=user)" --count-only
```

Usage
```text
USAGE:
  lq [options] [samAccountName|DN|SID|email|inputFile] [properties]

OPTIONS:
  -s, --server <server>[:port]    Specify the domain controller or GC host
  -f, --filter <ldapFilter>       LDAP filter (RFC 4515)
  -dn, --distinguishedname <dn>   Search by Distinguished Name (alias: --distinguished-name)
  -sid, --sid <sid>               Search by SID (e.g., S-1-5-21-...)
  -e, --email <email>             Search by email (mail attribute)
  -i, --input <file>              File with samAccountName, DN, SID, or email (one per line)
  -p, --properties <props>        Comma-separated list of properties (use * for default set)
  -o, --output <fmt>              Output format: json, csv (default is human-friendly)
  -u, --username <user>           Username for authentication
  -pw, --password <pass>          Password for authentication
  -c, --count                     Show object count after output
  -co, --count-only               Show only the object count (no query output)
  -h, --help                      Show help and exit
  -v, --version                   Show version and exit

ARGUMENTS:
  samAccountName|DN|SID|email|file
    If no filter or DN is specified, the first argument is treated as a
    samAccountName, Distinguished Name, SID, email, or an input file path.
  properties
    Comma-separated list of properties to retrieve (alternative to -p)
```

Behavior details
- Server default: If -s/--server is omitted, the current domain DNS name is used. If not discoverable, specify -s.
- GC auto-select: If neither -s nor -dn is provided and the search is by SID or email, the tool selects GC on port 3268.
- DN search strategy:
  1) Direct search under the DN's domain base (derived from DC= parts) using LDAP/GC per port
  2) Fallback filter (distinguishedName=<DN>)
  3) Parse CN/other attributes, search, then exact-DN filter
- Input files (-i):
  - Lines must be homogeneous: all DNs, all samAccountNames, all SIDs, or all emails
  - For samAccountName/SID/email: a single OR filter is built
  - For DN lists: each DN is resolved individually; missing DNs are reported to stderr
- Properties (-p):
  - -p name1,name2 limits attributes returned
  - -p * yields the default attribute set (no explicit PropertiesToLoad)
  - When exactly one property is requested and output format is default, only the value(s) are printed

Output formats
- default: aligned property list; colored when writing to a TTY
- json: array of objects
- csv: header includes all encountered keys; multi-valued attributes are ; separated

Attribute handling
- objectGUID: byte[] -> canonical GUID string
- objectSid: byte[] -> SDDL string (S-1-...); falls back to hex on decode errors
- Windows FILETIME attributes (lastLogon, lastLogonTimestamp, pwdLastSet, accountExpires,
  badPasswordTime, lastLogoff, lockoutTime, whenCreated, whenChanged):
  - Converted to ISO 8601 (O) in local time; 0/Int64.MaxValue -> "Never"
- Other byte[] attributes are rendered as hex

Exit codes
- 0: success (or after --help/--version)
- 1: usage/validation error
- 2: runtime/search error

Security
- Passing credentials with -u/-pw exposes them to shell history and process lists; prefer integrated auth when possible.

Limitations
- System.DirectoryServices targets Windows.
- LDAPS specifics are not explicitly configured; supplying :636 relies on DC configuration.

Contributing
Issues and PRs are welcome.

License
Add a license for this project (e.g., MIT) in a LICENSE file.
