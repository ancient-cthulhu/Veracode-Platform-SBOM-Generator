# Veracode SBOM Generator

Generate Software Bills of Materials (SBOMs) from the Veracode platform via CLI.

## Prerequisites

**API Credentials** - Requires one of:
- API Service Account with **Results API** role
- User Account with **Administrator**, **Reviewer**, or **Security Lead** role

**Setup:**
```ini
# ~/.veracode/credentials (Mac/Linux)
# C:\Users\<username>\.veracode\credentials (Windows)

[default]
veracode_api_key_id = YOUR_API_KEY_ID
veracode_api_key_secret = YOUR_API_KEY_SECRET
```

**Install:**
```bash
pip install requests veracode-api-signing
```

## Features

- **Multiple Targets**: Single app, multiple apps, collections, agent-based projects, entire workspaces
- **SBOM Formats**: CycloneDX v1.4 and SPDX v2.3 (JSON)
- **Multi-Region**: Commercial, European, and Federal regions
- **Interactive CLI**: Menu-driven interface or scriptable command-line mode

## Quick Start

**Interactive mode:**
```bash
python script.py
```

**Single application:**
```bash
python script.py --app "MyApp" --format cyclonedx
```

**Collection:**
```bash
python script.py --collection "MyCollection" --format spdx
```

**Agent-based project:**
```bash
python script.py --workspace "MyWorkspace" --project "MyProject"
```

**All projects in workspace:**
```bash
python script.py --workspace "MyWorkspace"
```

## Command-Line Arguments

| Argument | Short | Default | Description |
|----------|-------|---------|-------------|
| `--app` | `-a` | - | Application profile name |
| `--collection` | `-c` | - | Collection name |
| `--workspace` | `-w` | - | SCA workspace name |
| `--project` | `-p` | - | SCA project name (requires `--workspace`) |
| `--format` | `-f` | `cyclonedx` | SBOM format: `cyclonedx` or `spdx` |
| `--linked` | `-l` | `false` | Include linked agent-based scan results |
| `--no-vulns` | - | `false` | Exclude vulnerability information |
| `--output` | `-o` | `sbom_output` | Output directory |
| `--region` | `-r` | `commercial` | Region: `commercial`, `european`, `federal` |

## Output

SBOMs are saved to `sbom_output/` directory:

| Target | Output Path |
|--------|-------------|
| Single app | `sbom_output/<app_name>_sbom_<timestamp>.json` |
| Collection | `sbom_output/collection_<name>_<timestamp>/<app>_sbom.json` |
| Workspace | `sbom_output/workspace_<name>_<timestamp>/<project>_sbom.json` |

## API Endpoints

| Feature | Endpoint |
|---------|----------|
| Applications | `GET /appsec/v1/applications` |
| Collections | `GET /appsec/v1/collections` |
| Collection Assets | `GET /appsec/v1/collections/{guid}/assets` |
| Workspaces | `GET /srcclr/v3/workspaces` |
| Projects | `GET /srcclr/v3/workspaces/{guid}/projects` |
| SBOM (Application) | `GET /srcclr/sbom/v1/targets/{guid}/cyclonedx?type=application` |
| SBOM (Agent) | `GET /srcclr/sbom/v1/targets/{guid}/cyclonedx?type=agent` |

## Troubleshooting

| Issue | Solution |
|-------|----------|
| 401 Authentication failed | Verify API credentials in `~/.veracode/credentials` |
| 403 Access denied | Confirm account has required roles |
| No SCA results | Ensure at least one SCA scan completed in last 13 months |
| Collections not found | Collections require Early Adopter program access |

## References

- [Veracode SBOM API](https://docs.veracode.com/r/Generate_an_SBOM_with_the_REST_API)
- [API Authentication](https://docs.veracode.com/r/c_enabling_hmac)
- [veracode-api-signing](https://pypi.org/project/veracode-api-signing/)
