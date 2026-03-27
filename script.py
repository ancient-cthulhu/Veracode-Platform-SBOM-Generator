#!/usr/bin/env python3
"""Veracode SBOM Generator - Generate SBOMs from Veracode platform"""

import os
import re
import sys
import json
import logging
import argparse
from datetime import datetime
from dataclasses import dataclass
from typing import Optional, List, Dict, Tuple
from urllib.parse import urlparse, parse_qs

try:
    import requests
    from veracode_api_signing.plugin_requests import RequestsAuthPluginVeracodeHMAC
except ImportError:
    print("Error: Required packages not installed.")
    print("Please run: pip install requests veracode-api-signing")
    sys.exit(1)

logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

UNSAFE_FILENAME_CHARS = re.compile(r'[/\\:*?"<>| ]')
REQUEST_TIMEOUT = 30


@dataclass
class SBOMResult:
    guid: str
    name: str
    sbom: Optional[Dict]
    
    @property
    def success(self) -> bool:
        return self.sbom is not None


class VeracodeSBOMGenerator:
    
    REGIONS = {
        "commercial": "https://api.veracode.com",
        "european": "https://api.veracode.eu", 
        "federal": "https://api.veracode.us"
    }
    
    ENDPOINTS = {
        "applications": "/appsec/v1/applications",
        "collections": "/appsec/v1/collections",
        "workspaces": "/srcclr/v3/workspaces",
    }
    
    def __init__(self, region: str = "commercial"):
        self.base_url = self.REGIONS.get(region.lower(), self.REGIONS["commercial"])
        self.session = requests.Session()
        self.session.auth = RequestsAuthPluginVeracodeHMAC()
        self.session.headers.update({
            "User-Agent": "Veracode-SBOM-Generator/1.0",
            "Content-Type": "application/json"
        })
        
    def __enter__(self):
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.close()
        return False
        
    def _make_request(self, endpoint: str, params: Optional[Dict] = None) -> Dict:
        url = f"{self.base_url}{endpoint}"
        try:
            response = self.session.get(url, params=params, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            logger.error("Request timed out: %s", endpoint)
            return {}
        except requests.exceptions.HTTPError as e:
            status = e.response.status_code if e.response is not None else "unknown"
            messages = {
                401: "Authentication failed. Check your API credentials.",
                403: "Access denied.",
                404: f"Resource not found: {endpoint}",
            }
            logger.error("[%s] %s", status, messages.get(status, str(e)))
            return {}
        except requests.exceptions.RequestException as e:
            logger.error("Request failed: %s", e)
            return {}
    
    def _extract_embedded(self, result: Dict, key: str) -> List[Dict]:
        if not result:
            return []
        return result.get("_embedded", {}).get(key, [])
    
    def _get_all_pages(self, endpoint: str, embedded_key: str, params: Optional[Dict] = None) -> List[Dict]:
        """Generic pagination handler using _links.next or page object."""
        all_items: List[Dict] = []
        current_params = params.copy() if params else {}
        current_endpoint = endpoint
        
        while True:
            result = self._make_request(current_endpoint, current_params)
            items = self._extract_embedded(result, embedded_key)
            
            if not items:
                break
            
            all_items.extend(items)
            
            # Check for _links.next pagination (HAL format)
            links = result.get("_links", {})
            next_link = links.get("next", {}).get("href")
            if next_link:
                parsed = urlparse(next_link)
                current_endpoint = parsed.path
                current_params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
                continue
            
            # Check for page-based pagination
            page_info = result.get("page", {})
            if page_info:
                current_page = page_info.get("number", 0)
                total_pages = page_info.get("total_pages", 1)
                if current_page < total_pages - 1:
                    current_params["page"] = current_page + 1
                    continue
            
            break
        
        return all_items
    
    def _get_sbom(self, target_guid: str, sbom_format: str, target_type: str = "application",
                  include_linked: bool = False, include_vulnerabilities: bool = True) -> Optional[Dict]:
        endpoint = f"/srcclr/sbom/v1/targets/{target_guid}/{sbom_format}"
        params = {
            "type": target_type,
            "vulnerability": str(include_vulnerabilities).lower()
        }
        if target_type == "application" and include_linked:
            params["linked"] = "true"
        return self._make_request(endpoint, params) or None
    
    def get_applications(self, name_filter: Optional[str] = None, page_size: int = 100) -> List[Dict]:
        params = {"size": page_size}
        if name_filter:
            params["name"] = name_filter
        return self._get_all_pages(self.ENDPOINTS["applications"], "applications", params)
    
    def get_application_by_name(self, app_name: str) -> Optional[Dict]:
        apps = self.get_applications(name_filter=app_name)
        app_name_lower = app_name.lower()
        return next(
            (app for app in apps if app.get("profile", {}).get("name", "").lower() == app_name_lower),
            None
        )
    
    def generate_app_sbom(self, app_guid: str, sbom_format: str = "cyclonedx",
                          include_linked: bool = False, 
                          include_vulnerabilities: bool = True) -> Optional[Dict]:
        return self._get_sbom(app_guid, sbom_format, "application", include_linked, include_vulnerabilities)
    
    def get_collections(self) -> List[Dict]:
        return self._get_all_pages(self.ENDPOINTS["collections"], "collections")
    
    def get_collection_by_name(self, collection_name: str) -> Optional[Dict]:
        name_lower = collection_name.lower()
        return next((c for c in self.get_collections() if c.get("name", "").lower() == name_lower), None)
    
    def get_collection_assets(self, collection_guid: str) -> List[Dict]:
        return self._get_all_pages(f"{self.ENDPOINTS['collections']}/{collection_guid}/assets", "assets")
    
    def generate_collection_sboms(self, collection_guid: str, sbom_format: str = "cyclonedx",
                                   include_linked: bool = False,
                                   include_vulnerabilities: bool = True) -> List[SBOMResult]:
        assets = self.get_collection_assets(collection_guid)
        total = len(assets)
        logger.info("\nFound %d applications in collection", total)
        
        results: List[SBOMResult] = []
        for i, asset in enumerate(assets, 1):
            app_guid = asset.get("guid", "")
            app_name = asset.get("name", "Unknown")
            logger.info("   [%d/%d] Generating SBOM for: %s", i, total, app_name)
            sbom = self.generate_app_sbom(app_guid, sbom_format, include_linked, include_vulnerabilities)
            results.append(SBOMResult(guid=app_guid, name=app_name, sbom=sbom))
        return results
    
    def get_workspaces(self) -> List[Dict]:
        return self._get_all_pages(self.ENDPOINTS["workspaces"], "workspaces")
    
    def get_workspace_by_name(self, workspace_name: str) -> Optional[Dict]:
        name_lower = workspace_name.lower()
        return next((ws for ws in self.get_workspaces() if ws.get("name", "").lower() == name_lower), None)
    
    def get_workspace_projects(self, workspace_guid: str) -> List[Dict]:
        return self._get_all_pages(f"{self.ENDPOINTS['workspaces']}/{workspace_guid}/projects", "projects")
    
    def get_project_by_name(self, workspace_guid: str, project_name: str) -> Optional[Dict]:
        name_lower = project_name.lower()
        return next(
            (p for p in self.get_workspace_projects(workspace_guid) if p.get("name", "").lower() == name_lower),
            None
        )
    
    def generate_agent_sbom(self, project_guid: str, sbom_format: str = "cyclonedx",
                            include_vulnerabilities: bool = True) -> Optional[Dict]:
        return self._get_sbom(project_guid, sbom_format, "agent", False, include_vulnerabilities)
    
    def generate_workspace_sboms(self, workspace_guid: str, sbom_format: str = "cyclonedx",
                                  include_vulnerabilities: bool = True) -> List[SBOMResult]:
        projects = self.get_workspace_projects(workspace_guid)
        total = len(projects)
        logger.info("\nFound %d projects in workspace", total)
        
        results: List[SBOMResult] = []
        for i, project in enumerate(projects, 1):
            project_guid = project.get("id", "")
            project_name = project.get("name", "Unknown")
            logger.info("   [%d/%d] Generating SBOM for: %s", i, total, project_name)
            sbom = self.generate_agent_sbom(project_guid, sbom_format, include_vulnerabilities)
            results.append(SBOMResult(guid=project_guid, name=project_name, sbom=sbom))
        return results


def clear_screen() -> None:
    print("\033[2J\033[H", end="", flush=True)


def print_header() -> None:
    print("=" * 60)
    print("       VERACODE SBOM GENERATOR")
    print("=" * 60)
    print()


def print_menu() -> None:
    print("\nMAIN MENU")
    print("-" * 40)
    print("  1. Single Application Profile")
    print("  2. Multiple Application Profiles")
    print("  3. Collection (Aggregated Apps)")
    print("  4. Agent-Based Scanning Project")
    print("  5. All Projects in a Workspace")
    print("-" * 40)
    print("  6. List All Applications")
    print("  7. List All Collections")
    print("  8. List All Workspaces")
    print("-" * 40)
    print("  0. Exit")
    print()


def select_format() -> str:
    print("\nSELECT SBOM FORMAT")
    print("-" * 40)
    print("  1. CycloneDX (JSON)")
    print("  2. SPDX (JSON)")
    print()
    while True:
        choice = input("Enter choice [1-2]: ").strip()
        if choice == "1":
            return "cyclonedx"
        if choice == "2":
            return "spdx"
        print("Invalid choice. Please enter 1 or 2.")


def select_options() -> Tuple[bool, bool]:
    print("\nSBOM OPTIONS")
    print("-" * 40)
    include_linked = input("Include linked agent-based results? [y/N]: ").strip().lower() == 'y'
    include_vulns = input("Include vulnerabilities? [Y/n]: ").strip().lower() != 'n'
    return include_linked, include_vulns


def save_sbom(sbom_data: Dict, filename: str, output_dir: str = ".") -> bool:
    try:
        os.makedirs(output_dir, exist_ok=True)
        filepath = os.path.join(output_dir, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            json.dump(sbom_data, f, indent=2)
        logger.info("   Saved: %s", filepath)
        return True
    except (OSError, IOError, TypeError, ValueError) as e:
        logger.error("   Failed to save %s: %s", filename, e)
        return False


def sanitize_filename(name: str) -> str:
    return UNSAFE_FILENAME_CHARS.sub('_', name)


def select_from_list(items: List[Dict], prompt: str, name_key: str = "name") -> Optional[Dict]:
    if not items:
        return None
    print(f"\nAvailable ({len(items)}):")
    for i, item in enumerate(items, 1):
        print(f"  {i}. {item.get(name_key, 'Unknown')}")
    choice = input(f"\n{prompt}: ").strip()
    try:
        index = int(choice) - 1
        if 0 <= index < len(items):
            return items[index]
    except ValueError:
        pass
    print("Invalid selection.")
    return None


def process_sbom_results(results: List[SBOMResult], output_dir: str) -> int:
    return sum(1 for r in results if r.sbom and save_sbom(r.sbom, f"{sanitize_filename(r.name)}_sbom.json", output_dir))


def interactive_mode(generator: VeracodeSBOMGenerator) -> None:
    while True:
        clear_screen()
        print_header()
        print_menu()
        choice = input("Enter choice: ").strip()
        
        if choice == "0":
            print("\nGoodbye!")
            sys.exit(0)
            
        elif choice == "1":
            print("\nSINGLE APPLICATION PROFILE")
            print("-" * 40)
            app_name = input("Enter application name: ").strip()
            if not app_name:
                print("Error: Application name cannot be empty.")
                input("\nPress Enter to continue...")
                continue
            
            print(f"\nSearching for application: {app_name}")
            app = generator.get_application_by_name(app_name)
            if not app:
                print(f"Error: Application '{app_name}' not found.")
                input("\nPress Enter to continue...")
                continue
            
            app_guid = app.get("guid")
            actual_name = app.get("profile", {}).get("name", app_name)
            print(f"Found: {actual_name} ({app_guid})")
            
            sbom_format = select_format()
            include_linked, include_vulns = select_options()
            
            print(f"\nGenerating {sbom_format.upper()} SBOM...")
            sbom = generator.generate_app_sbom(app_guid, sbom_format, include_linked, include_vulns)
            
            if sbom:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_sbom(sbom, f"{sanitize_filename(actual_name)}_sbom_{timestamp}.json", "sbom_output")
            else:
                print("Error: Failed to generate SBOM. The application may not have SCA scan results.")
            input("\nPress Enter to continue...")
            
        elif choice == "2":
            print("\nMULTIPLE APPLICATION PROFILES")
            print("-" * 40)
            print("Enter application names (one per line, empty line to finish):")
            app_names: List[str] = []
            while True:
                name = input("  App name: ").strip()
                if not name:
                    break
                app_names.append(name)
            
            if not app_names:
                print("Error: No applications specified.")
                input("\nPress Enter to continue...")
                continue
            
            sbom_format = select_format()
            include_linked, include_vulns = select_options()
            print(f"\nGenerating SBOMs for {len(app_names)} applications...")
            
            success_count = 0
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            for i, name in enumerate(app_names, 1):
                print(f"\n[{i}/{len(app_names)}] Processing: {name}")
                app = generator.get_application_by_name(name)
                if not app:
                    print(f"   Error: Application not found: {name}")
                    continue
                actual_name = app.get("profile", {}).get("name", name)
                sbom = generator.generate_app_sbom(app.get("guid"), sbom_format, include_linked, include_vulns)
                if sbom and save_sbom(sbom, f"{sanitize_filename(actual_name)}_sbom_{timestamp}.json", "sbom_output"):
                    success_count += 1
                elif not sbom:
                    print(f"   Error: Failed to generate SBOM for {actual_name}")
            
            print(f"\nSummary: {success_count}/{len(app_names)} SBOMs generated successfully")
            input("\nPress Enter to continue...")
            
        elif choice == "3":
            print("\nCOLLECTION")
            print("-" * 40)
            collection_name = input("Enter collection name: ").strip()
            if not collection_name:
                print("Error: Collection name cannot be empty.")
                input("\nPress Enter to continue...")
                continue
            
            print(f"\nSearching for collection: {collection_name}")
            collection = generator.get_collection_by_name(collection_name)
            if not collection:
                print(f"Error: Collection '{collection_name}' not found.")
                input("\nPress Enter to continue...")
                continue
            
            actual_name = collection.get("name", collection_name)
            print(f"Found: {actual_name} ({collection.get('guid')})")
            
            sbom_format = select_format()
            include_linked, include_vulns = select_options()
            print("\nGenerating SBOMs for collection...")
            
            results = generator.generate_collection_sboms(collection.get("guid"), sbom_format, include_linked, include_vulns)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"sbom_output/collection_{sanitize_filename(actual_name)}_{timestamp}"
            success_count = process_sbom_results(results, output_dir)
            
            print(f"\nSummary: {success_count}/{len(results)} SBOMs generated successfully")
            print(f"   Output directory: {output_dir}")
            input("\nPress Enter to continue...")
            
        elif choice == "4":
            print("\nAGENT-BASED SCANNING PROJECT")
            print("-" * 40)
            print("Fetching workspaces...")
            workspace = select_from_list(generator.get_workspaces(), "Select workspace number")
            if not workspace:
                input("\nPress Enter to continue...")
                continue
            
            print(f"\nFetching projects for workspace: {workspace.get('name')}")
            project = select_from_list(generator.get_workspace_projects(workspace.get("id")), "Select project number")
            if not project:
                input("\nPress Enter to continue...")
                continue
            
            project_name = project.get("name", "Unknown")
            sbom_format = select_format()
            include_vulns = input("Include vulnerabilities? [Y/n]: ").strip().lower() != 'n'
            
            print(f"\nGenerating {sbom_format.upper()} SBOM for project: {project_name}")
            sbom = generator.generate_agent_sbom(project.get("id"), sbom_format, include_vulns)
            
            if sbom:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                save_sbom(sbom, f"{sanitize_filename(project_name)}_agent_sbom_{timestamp}.json", "sbom_output")
            else:
                print("Error: Failed to generate SBOM. The project may not have recent scan results.")
            input("\nPress Enter to continue...")
            
        elif choice == "5":
            print("\nALL PROJECTS IN WORKSPACE")
            print("-" * 40)
            print("Fetching workspaces...")
            workspace = select_from_list(generator.get_workspaces(), "Select workspace number")
            if not workspace:
                input("\nPress Enter to continue...")
                continue
            
            workspace_name = workspace.get("name", "Unknown")
            sbom_format = select_format()
            include_vulns = input("Include vulnerabilities? [Y/n]: ").strip().lower() != 'n'
            
            print(f"\nGenerating SBOMs for all projects in workspace: {workspace_name}")
            results = generator.generate_workspace_sboms(workspace.get("id"), sbom_format, include_vulns)
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_dir = f"sbom_output/workspace_{sanitize_filename(workspace_name)}_{timestamp}"
            success_count = process_sbom_results(results, output_dir)
            
            print(f"\nSummary: {success_count}/{len(results)} SBOMs generated successfully")
            print(f"   Output directory: {output_dir}")
            input("\nPress Enter to continue...")
            
        elif choice == "6":
            print("\nALL APPLICATIONS")
            print("-" * 40)
            print("Fetching applications...")
            apps = generator.get_applications()
            if not apps:
                print("Error: No applications found or failed to fetch.")
            else:
                print(f"\nFound {len(apps)} applications:\n")
                for i, app in enumerate(apps, 1):
                    print(f"  {i:3d}. {app.get('profile', {}).get('name', 'Unknown')}")
                    print(f"       GUID: {app.get('guid', 'N/A')}")
            input("\nPress Enter to continue...")
            
        elif choice == "7":
            print("\nALL COLLECTIONS")
            print("-" * 40)
            print("Fetching collections...")
            collections = generator.get_collections()
            if not collections:
                print("Error: No collections found or failed to fetch.")
            else:
                print(f"\nFound {len(collections)} collections:\n")
                for i, col in enumerate(collections, 1):
                    print(f"  {i:3d}. {col.get('name', 'Unknown')}")
                    print(f"       GUID: {col.get('guid', 'N/A')}")
            input("\nPress Enter to continue...")
            
        elif choice == "8":
            print("\nALL WORKSPACES")
            print("-" * 40)
            print("Fetching workspaces...")
            workspaces = generator.get_workspaces()
            if not workspaces:
                print("Error: No workspaces found or failed to fetch.")
            else:
                print(f"\nFound {len(workspaces)} workspaces:\n")
                for i, ws in enumerate(workspaces, 1):
                    print(f"  {i:3d}. {ws.get('name', 'Unknown')}")
                    print(f"       ID: {ws.get('id', 'N/A')}")
            input("\nPress Enter to continue...")
            
        else:
            print("Error: Invalid choice. Please try again.")
            input("\nPress Enter to continue...")


def command_line_mode(args: argparse.Namespace) -> None:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or "sbom_output"
    
    with VeracodeSBOMGenerator(region=args.region) as generator:
        if args.app:
            logger.info("Fetching application: %s", args.app)
            app = generator.get_application_by_name(args.app)
            if not app:
                logger.error("Error: Application '%s' not found.", args.app)
                sys.exit(1)
            
            app_name = app.get("profile", {}).get("name", args.app)
            logger.info("Generating %s SBOM for: %s", args.format.upper(), app_name)
            sbom = generator.generate_app_sbom(app.get("guid"), args.format, args.linked, not args.no_vulns)
            
            if sbom:
                save_sbom(sbom, f"{sanitize_filename(app_name)}_sbom_{timestamp}.json", output_dir)
            else:
                logger.error("Failed to generate SBOM.")
                sys.exit(1)
                
        elif args.collection:
            logger.info("Fetching collection: %s", args.collection)
            collection = generator.get_collection_by_name(args.collection)
            if not collection:
                logger.error("Error: Collection '%s' not found.", args.collection)
                sys.exit(1)
            
            collection_name = collection.get("name", args.collection)
            logger.info("Generating SBOMs for collection: %s", collection_name)
            results = generator.generate_collection_sboms(collection.get("guid"), args.format, args.linked, not args.no_vulns)
            
            col_output_dir = os.path.join(output_dir, f"collection_{sanitize_filename(collection_name)}_{timestamp}")
            success_count = process_sbom_results(results, col_output_dir)
            logger.info("\nSummary: %d/%d SBOMs generated", success_count, len(results))
            
        elif args.workspace and args.project:
            logger.info("Fetching workspace: %s", args.workspace)
            workspace = generator.get_workspace_by_name(args.workspace)
            if not workspace:
                logger.error("Error: Workspace '%s' not found.", args.workspace)
                sys.exit(1)
            
            project = generator.get_project_by_name(workspace.get("id"), args.project)
            if not project:
                logger.error("Error: Project '%s' not found in workspace.", args.project)
                sys.exit(1)
            
            project_name = project.get("name", args.project)
            logger.info("Generating %s SBOM for project: %s", args.format.upper(), project_name)
            sbom = generator.generate_agent_sbom(project.get("id"), args.format, not args.no_vulns)
            
            if sbom:
                save_sbom(sbom, f"{sanitize_filename(project_name)}_agent_sbom_{timestamp}.json", output_dir)
            else:
                logger.error("Failed to generate SBOM.")
                sys.exit(1)
                
        elif args.workspace:
            logger.info("Fetching workspace: %s", args.workspace)
            workspace = generator.get_workspace_by_name(args.workspace)
            if not workspace:
                logger.error("Error: Workspace '%s' not found.", args.workspace)
                sys.exit(1)
            
            workspace_name = workspace.get("name", args.workspace)
            logger.info("Generating SBOMs for all projects in workspace: %s", workspace_name)
            results = generator.generate_workspace_sboms(workspace.get("id"), args.format, not args.no_vulns)
            
            ws_output_dir = os.path.join(output_dir, f"workspace_{sanitize_filename(workspace_name)}_{timestamp}")
            success_count = process_sbom_results(results, ws_output_dir)
            logger.info("\nSummary: %d/%d SBOMs generated", success_count, len(results))
        
        else:
            logger.error("Error: No target specified. Use --app, --collection, or --workspace.")
            sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Veracode SBOM Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Interactive mode:     python script.py
  Single application:   python script.py --app "MyApp" --format cyclonedx
  Collection:           python script.py --collection "MyCollection" --format spdx
  Agent project:        python script.py --workspace "MyWorkspace" --project "MyProject"
  All workspace:        python script.py --workspace "MyWorkspace"
        """
    )
    
    target_group = parser.add_argument_group("Target Options")
    target_group.add_argument("--app", "-a", help="Application profile name")
    target_group.add_argument("--collection", "-c", help="Collection name")
    target_group.add_argument("--workspace", "-w", help="SCA workspace name")
    target_group.add_argument("--project", "-p", help="SCA project name (requires --workspace)")
    
    format_group = parser.add_argument_group("Format Options")
    format_group.add_argument("--format", "-f", choices=["cyclonedx", "spdx"], default="cyclonedx",
                              help="SBOM format (default: cyclonedx)")
    
    options_group = parser.add_argument_group("Additional Options")
    options_group.add_argument("--linked", "-l", action="store_true", help="Include linked agent-based scan results")
    options_group.add_argument("--no-vulns", action="store_true", help="Exclude vulnerability information")
    options_group.add_argument("--output", "-o", help="Output directory (default: sbom_output)")
    options_group.add_argument("--region", "-r", choices=["commercial", "european", "federal"],
                               default="commercial", help="Veracode region (default: commercial)")
    
    args = parser.parse_args()
    
    if not os.environ.get("VERACODE_API_KEY_ID") and not os.path.exists(os.path.expanduser("~/.veracode/credentials")):
        logger.warning("Warning: Veracode API credentials not found.")
        logger.warning("   Set VERACODE_API_KEY_ID and VERACODE_API_KEY_SECRET environment variables")
        logger.warning("   Or create ~/.veracode/credentials file\n")
    
    if any([args.app, args.collection, args.workspace]):
        command_line_mode(args)
    else:
        with VeracodeSBOMGenerator(region=args.region) as generator:
            interactive_mode(generator)


if __name__ == "__main__":
    main()
