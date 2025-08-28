# lq

LDAP query console utility for Active Directory on .NET 8.

lq lets you:
- Query Active Directory over LDAP or Global Catalog
- Search by LDAP filter or by Distinguished Name (DN)
- Choose specific attributes to return
- Print results as a pretty table, CSV, or JSON
- Decode common AD types (objectSid, objectGuid, FILETIME) for readability

Note: This tool uses System.DirectoryServices and is supported on Windows.

## Requirements
- Windows
- .NET 8 SDK (for build and run)
- Network connectivity to a domain controller or GC
- Optional credentials if the running context does not have access

## Install / Build
```bash
# Clone and build
git clone https://github.com/benny-ojeda/lq
cd lq

# Build
 dotnet build -c Release

# Run (from source)
 dotnet run --project lq -- -h

# Or publish a single-file executable (win-x64)
 dotnet publish lq -c Release -r win-x64 -p:PublishSingleFile=true --self-contained false
```
The published executable will be in lq/bin/Release/net8.0/win-x64/publish.

## Quick start
```bash
# Search by filter on default domain controller (current domain)
lq -f "(samaccountname=jdoe)"

# Search a GC (port 3268); useful for forest-wide lookups
lq -s dc1.contoso.com:3268 -f "(objectClass=user)" -o table

# Search by Distinguished Name (DN)
lq -dn "CN=John Doe,OU=Users,DC=contoso,DC=com" -p cn,mail

# Same as filter; positional argument becomes (samaccountname=<value>)
lq jdoe cn,mail

# Bulk search from file (one samAccountName per line)
lq -i users.txt -p cn,mail -o csv

# JSON output
lq -s dc1 -f "(objectClass=computer)" -o json
```

## Usage
```text
USAGE:
  lq [options] [samAccountName] [properties]

OPTIONS:
  -s, --server <server>[:port]    Specify the domain controller or GC host
  -f, --filter <ldapFilter>       LDAP filter (RFC 4515)
  -dn, --distinguished-name <dn>  Search by Distinguished Name
  -i, --input <file>              File with samAccountName (one per line)
  -p, --properties <props>        Comma-separated list of properties
  -o, --output <fmt>              Output format: table, json, csv
  -u, --username <user>           Username for authentication
  -w, --password <pass>           Password for authentication
  -h, --help                      Show help and exit
  -v, --version                   Show version and exit

ARGUMENTS:
  samAccountName                  If no filter or DN is specified, used as
                                  (samaccountname=<value>)
  properties                      Comma-separated list of properties to retrieve
                                  (alternative to -p switch)
```

Notes:
- If --server is omitted, lq attempts to use the current Active Directory domain name.
- If you pass :3268, lq uses the GC protocol (GC://); otherwise LDAP (LDAP://).
- A single property selection (e.g., -p cn) prints only the value(s) of that property.
- Use -p * to return “all” properties (default behavior).
- Attribute names in the output are typically lowercase (as returned by AD). When requesting a single property, prefer lowercase (e.g., cn, mail, distinguishedname).

## Output formats
- table (default): human-friendly aligned text with colors when writing to a TTY
- csv: header + rows, multi-valued attributes are joined with “;”
- json: array of objects

Example (table):
```text
cn     : John Doe
mail   : john.doe@contoso.com
dn     : CN=John Doe,OU=Users,DC=contoso,DC=com
...
```

## Attribute handling
lq converts common AD attribute types into readable forms:
- objectGuid: byte[] -> canonical GUID string
- objectSid: byte[] -> SID string (S-1-5-...) when possible
- Windows FILETIME attributes (e.g., lastlogon, lastlogontimestamp, pwdlastset, accountexpires, badpasswordtime, lastlogoff, lockouttime, whencreated, whenchanged) -> localized ISO 8601 (O) format; “Never” for 0 or Int64.MaxValue
- Other byte[] attributes are shown as hex

## DN search behavior
When using -dn/--distinguished-name:
1) Direct DN search under the object’s domain base (derived from DC= parts of the DN)
2) Fallback to filter: (distinguishedName=<DN>)
3) Heuristic component search (CN or other RDNs), filtered back to the exact DN

## Input file format (-i)
- Plain text
- One samAccountName per line
- Blank lines are ignored
- Invalid names terminate with a non-zero exit code

Example:
```text
jdoe
asmith
svc_backup$
```

## Exit codes
- 0: success (or after --help/--version)
- 1: usage/validation error
- 2: runtime/search error

## Security
- Passing credentials with -u/-w exposes them to shell history and process listings. Use a protected session, or rely on integrated authentication when possible.

## Limitations
- System.DirectoryServices is Windows-only.
- LDAPS specifics are not explicitly configured; providing :636 may work if the DC is properly configured.
- Property name matching in single-property output is case-sensitive; prefer lowercase names.

## Contributing
Issues and PRs are welcome.

## License
Add a license for this project (e.g., MIT) in a LICENSE file.
