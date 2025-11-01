import logging
import os
import re
import shlex
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import glob

# Import the HTML report generator
from .sum_report_gen import parse_sum_report_to_html

# Import ZTP functionality for power management
import app.ZTP as ZTP

# Constants
CHECKFIRMWARE_EXEC = "/usr/sbin/smartupdate"
DEFAULT_TIMEOUT = 1800  # 30 minutes for inventory
INVENTORY_CHECK_INTERVAL = 60  # Check every 60 seconds (1 minute)
MAX_INVENTORY_ATTEMPTS = 30  # Up to 30 minutes total
REPORT_BASE_PATH = "/pub/reports/sum"
PERMISSION_MODE = "755"  # Changed to 755 for readable by everyone

# Initialize global variable
_first_smartupdate_called = False

# Configure logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)  # Set to DEBUG for troubleshooting


def run_cmd(cmd: List[str], timeout: int = DEFAULT_TIMEOUT, return_dict: bool = False) -> Optional[str]:
    """Execute a subprocess command and return its output.
    
    Args:
        cmd: Command to execute
        timeout: Timeout in seconds
        return_dict: If True, return dict with success/output/error, else return string output
    """
    global _first_smartupdate_called

    is_smartupdate = len(cmd) >= 2 and cmd[1] == CHECKFIRMWARE_EXEC

    if is_smartupdate and not _first_smartupdate_called:
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=os.environ.copy(),
                stdin=subprocess.PIPE,
            )
            output, error = process.communicate(input="YES\n", timeout=timeout)
            _first_smartupdate_called = True
            if return_dict:
                return {
                    "success": process.returncode == 0,
                    "output": output,
                    "error": error,
                    "returncode": process.returncode
                }
            elif process.returncode == 0:
                return output
            else:
                logger.error(f"Command failed: {' '.join(cmd)} - Error: {error}")
                return None
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {' '.join(cmd)}")
            process.kill()
            process.communicate()
            if return_dict:
                return {"success": False, "output": "", "error": "Command timed out", "returncode": -1}
            return None
        except subprocess.SubprocessError as e:
            logger.error(f"Command failed: {' '.join(cmd)} - Error: {e}")
            if return_dict:
                return {"success": False, "output": "", "error": str(e), "returncode": -1}
            return None
    else:
        try:
            result = subprocess.run(
                cmd, check=True, capture_output=True, text=True, timeout=timeout, env=os.environ.copy()
            )
            if return_dict:
                return {
                    "success": True,
                    "output": result.stdout,
                    "error": result.stderr,
                    "returncode": result.returncode
                }
            return result.stdout
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {' '.join(cmd)}")
            if return_dict:
                return {"success": False, "output": "", "error": "Command timed out", "returncode": -1}
            return None
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(cmd)} - Error: {e.stderr}")
            if return_dict:
                return {
                    "success": False,
                    "output": e.stdout or "",
                    "error": e.stderr or "",
                    "returncode": e.returncode
                }
            return None


def parse_node_status(output: str, lom: str) -> Optional[str]:
    """Parse node status from command output.
    
    Expected format from 'smartupdate getnodes <node_name>':
    1. mn053-2hz1-01s01lo.uhc.com
        Node Status: Update required
        Type: iLO 6
    """
    if not output:
        return None
        
    # Look for "Node Status:" line in the output
    for line in output.split('\n'):
        line = line.strip()
        if line.startswith('Node Status:'):
            status = line.split(':', 1)[1].strip()
            logger.debug(f"[{lom}] Parsed node status: {status}")
            return status
    
    # Fallback to original regex pattern for backwards compatibility
    match = re.search(rf"{lom}.*?Node Status:\s*([^\n]+)", output, re.DOTALL)
    if match:
        status = match.group(1).strip()
        logger.debug(f"[{lom}] Parsed node status (regex fallback): {status}")
        return status
    
    logger.debug(f"[{lom}] Could not parse node status from output")
    return None


def get_node_status(lom: str) -> Optional[str]:
    """Retrieve node status using 'getnodes <node_name>'."""
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "getnodes", lom]
    output = run_cmd(cmd)
    if output:
        logger.debug(f"[{lom}] Retrieved getnodes output successfully")
        return output
    logger.warning(f"[{lom}] Failed to retrieve getnodes output")
    return None


def wait_for_inventory_progress(lom: str) -> bool:
    """Wait for inventory process to complete with regular status updates.
    
    Monitors the node status every minute and provides progress updates.
    Expected status progression:
    - "Inventory started" -> inventory in progress
    - Any other status -> inventory completed (success or failure)
    
    Returns:
        bool: True if inventory completed, False if timed out
    """
    logger.info(f"[{lom}] Starting inventory progress monitoring (checking every {INVENTORY_CHECK_INTERVAL} seconds)")
    
    for attempt in range(MAX_INVENTORY_ATTEMPTS):
        output = get_node_status(lom)
        status = parse_node_status(output, lom) if output else None
        
        # Format the elapsed time
        elapsed_minutes = attempt + 1
        total_minutes = MAX_INVENTORY_ATTEMPTS
        
        if status:
            # Check if inventory is still in progress
            if status.lower() == "inventory started":
                logger.info(f"[{lom}] Inventory in progress... ({elapsed_minutes}/{total_minutes} minutes) - Status: {status}")
            else:
                # Inventory completed (could be success, error, or other final state)
                logger.info(f"[{lom}] Inventory completed after {elapsed_minutes} minutes - Final Status: {status}")
                return True
        else:
            logger.warning(f"[{lom}] No status retrieved from getnodes on attempt {elapsed_minutes}/{total_minutes}")
        
        # Don't sleep on the last attempt
        if attempt < MAX_INVENTORY_ATTEMPTS - 1:
            time.sleep(INVENTORY_CHECK_INTERVAL)
    
    logger.error(f"[{lom}] Inventory did not complete after {MAX_INVENTORY_ATTEMPTS} minutes - timed out")
    return False


def wait_for_deployment_progress(lom: str) -> bool:
    """Wait for deployment process to complete with regular status updates.
    
    Monitors the node status every minute and provides progress updates.
    Expected status progression:
    - "Deploy started" or "Deploying" or similar -> deployment in progress
    - Any other status -> deployment completed (success or failure)
    
    Returns:
        bool: True if deployment completed, False if timed out
    """
    DEPLOY_CHECK_INTERVAL = 60  # Check every 60 seconds (1 minute)
    MAX_DEPLOY_ATTEMPTS = 60   # Up to 60 minutes total for deployment
    
    logger.info(f"[{lom}] Starting deployment progress monitoring (checking every {DEPLOY_CHECK_INTERVAL} seconds)")
    
    for attempt in range(MAX_DEPLOY_ATTEMPTS):
        output = get_node_status(lom)
        status = parse_node_status(output, lom) if output else None
        
        # Format the elapsed time
        elapsed_minutes = attempt + 1
        total_minutes = MAX_DEPLOY_ATTEMPTS
        
        if status:
            # Check if deployment is still in progress
            status_lower = status.lower()
            if any(keyword in status_lower for keyword in ["deploy started", "deploying", "deployment in progress", "installing", "updating"]):
                logger.info(f"[{lom}] Deployment in progress... ({elapsed_minutes}/{total_minutes} minutes) - Status: {status}")
            else:
                # Deployment completed (could be success, error, or other final state)
                logger.info(f"[{lom}] Deployment completed after {elapsed_minutes} minutes - Final Status: {status}")
                return True
        else:
            logger.warning(f"[{lom}] No status retrieved from getnodes on attempt {elapsed_minutes}/{total_minutes}")
        
        # Don't sleep on the last attempt
        if attempt < MAX_DEPLOY_ATTEMPTS - 1:
            time.sleep(DEPLOY_CHECK_INTERVAL)
    
    logger.error(f"[{lom}] Deployment did not complete after {MAX_DEPLOY_ATTEMPTS} minutes - timed out")
    return False


def parse_report_paths(report_output: str, lom: str) -> List[str]:
    """Parse report paths from command output (CSV files only for deploy preview)."""
    report_paths = []
    # Updated pattern to match only CSV files since we're using --output csv
    path_pattern = re.compile(r"(/pub/reports/[^ \n]+\.csv)")
    
    for match in path_pattern.finditer(report_output):
        path = match.group(1)
        if Path(path).exists():
            report_paths.append(path)
            logger.debug(f"[{lom}] Found report path: {path}")
        else:
            logger.warning(f"[{lom}] Report path {path} not found on filesystem")
    return report_paths


def parse_attributes_output(output: Optional[str]) -> Dict[str, str]:
    """Parse attributes from command output."""
    attributes = {}
    if output:
        for line in output.strip().split("\n"):
            if ":" in line and line.strip():
                try:
                    key, value = map(str.strip, line.split(":", 1))
                    attributes[key] = value
                except ValueError:
                    continue
    return attributes


def set_readable_permissions(path: str, lom: str) -> bool:
    """Set permissions to make files/directories readable by everyone."""
    try:
        # Set 755 for directories and 644 for files to ensure readability
        if Path(path).is_dir():
            # For directories: 755 (rwxr-xr-x)
            subprocess.run(["sudo", "chmod", "-R", "755", path], check=True)
            logger.debug(f"[{lom}] Set directory permissions (755) for: {path}")
        else:
            # For files: 644 (rw-r--r--)
            subprocess.run(["sudo", "chmod", "644", path], check=True)
            logger.debug(f"[{lom}] Set file permissions (644) for: {path}")
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"[{lom}] Failed to set permissions for {path}: {e.stderr}")
        return False


def move_and_set_permissions(source_path: str, dest_path: str, lom: str) -> Optional[str]:
    """Move file/directory and set permissions for public readability."""
    try:
        if source_path != dest_path:
            subprocess.run(["sudo", "mv", source_path, dest_path], check=True)
            logger.info(f"[{lom}] Moved report from {source_path} to {dest_path}")
        
        # Set appropriate permissions for public readability
        if set_readable_permissions(dest_path, lom):
            return dest_path
        else:
            return None
            
    except subprocess.CalledProcessError as e:
        logger.error(f"[{lom}] Failed to move {source_path} to {dest_path}: {e.stderr}")
        return None


def prepare_report_directories(lom: str) -> Tuple[str, str, str, str]:
    """Prepare timestamped report and temporary directories."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = f"{REPORT_BASE_PATH}/{lom}/{timestamp}"
    reports_dir = os.path.join(base_dir, "reports")
    temp_dir = os.path.join(base_dir, "temp")
    
    # Create directories with proper permissions
    os.makedirs(reports_dir, exist_ok=True)
    os.makedirs(temp_dir, exist_ok=True)
    
    # Ensure directories are readable by everyone
    try:
        subprocess.run(["sudo", "chmod", "-R", "755", base_dir], check=True)
        logger.debug(f"[{lom}] Set directory permissions for {base_dir}")
    except subprocess.CalledProcessError as e:
        logger.warning(f"[{lom}] Failed to set directory permissions for {base_dir}: {e.stderr}")
    
    return base_dir, reports_dir, temp_dir, timestamp


def generate_html_report(lom: str, reports_dir: str, base_dir: str, node_gen: str = None, baseline_path: str = None, run_time: str = None, update_required: bool = None) -> Optional[str]:
    """Generate HTML report from deploy preview CSV file generated by smartupdate."""
    try:
        # Look for any CSV file in the reports directory since we're only generating deploy preview
        csv_pattern = os.path.join(reports_dir, "*.csv")
        csv_files = glob.glob(csv_pattern)
        
        if not csv_files:
            logger.warning(f"[{lom}] No CSV file found in {reports_dir}")
            return None
        
        # Use the first (and should be only) CSV file
        csv_file = csv_files[0]
        logger.info(f"[{lom}] Found deploy preview CSV report: {csv_file}")
        
        # Read CSV content
        with open(csv_file, 'r', encoding='utf-8') as file:
            csv_content = file.read()
        
        # Generate HTML using sum_report_gen
        html_output = parse_sum_report_to_html(csv_content, server_name=lom, node_gen=node_gen, baseline_path=baseline_path, run_time=run_time, update_required=update_required)
        
        # Generate HTML filename in base_dir (not reports_dir)
        csv_filename = Path(csv_file).name
        base_name = os.path.splitext(csv_filename)[0]
        html_filename = f"{base_name}.html"
        html_filepath = os.path.join(base_dir, html_filename)
        
        # Write HTML file
        with open(html_filepath, 'w', encoding='utf-8') as file:
            file.write(html_output)
        
        # Set permissions for public readability
        if set_readable_permissions(html_filepath, lom):
            logger.info(f"[{lom}] Generated HTML report with public read permissions: {html_filepath}")
            return html_filepath
        else:
            logger.error(f"[{lom}] Failed to set permissions for HTML report: {html_filepath}")
            return None
        
    except Exception as e:
        logger.error(f"[{lom}] Failed to generate HTML report: {e}")
        return None


def generate_http_url(file_path: str) -> Optional[str]:
    """Generate HTTP URL from file path for web access.
    
    Converts local file paths under /pub/reports/sum to HTTP URLs.
    Example: /pub/reports/sum/node/timestamp/report.html -> http://server/pub/reports/sum/node/timestamp/report.html
    """
    if not file_path or not file_path.startswith("/pub/reports/sum"):
        return None
    
    # Keep the full path including /pub prefix for the HTTP URL
    # Assuming the web server serves /pub content with /pub in the URL
    
    # Get base URL from environment variable or use default
    base_url = os.environ.get("REPORT_BASE_URL", "http://bmi-dev.optum.com")
    return f"{base_url}{file_path}"


def calculate_execution_time(start_time: float) -> tuple:
    """Calculate execution time and return seconds and formatted string."""
    end_time = time.time()
    execution_time = end_time - start_time
    minutes = int(execution_time // 60)
    seconds = int(execution_time % 60)
    return round(execution_time, 2), f"{minutes}m {seconds}s"


def verify_and_set_node_attributes(lom: str) -> bool:
    """Verify and ensure node attributes are properly set for deployment."""
    required_attributes = {
        "ignore_warnings": "true",
        "ignore_tpm": "true", 
        "on_failed_dependency": "force",
        "skip_prereqs": "true"
    }
    
    # Get current attributes
    logger.info(f"[{lom}] Verifying node attributes")
    get_attr_cmd = ["sudo", CHECKFIRMWARE_EXEC, "getattributes", "--nodes", lom]
    logger.info(f"[{lom}] Running command: {' '.join(get_attr_cmd)}")
    attr_output = run_cmd(get_attr_cmd)
    
    if not attr_output:
        logger.warning(f"[{lom}] Failed to get node attributes")
        return False
    
    # Log the full getattributes output for verification
    logger.info(f"[{lom}] getattributes output:")
    logger.info(f"[{lom}] ATTRIBUTES START")
    logger.info(attr_output)
    logger.info(f"[{lom}] ATTRIBUTES END")
    
    # Parse attributes
    current_attributes = parse_attributes_output(attr_output)
    
    # Check if required attributes are set correctly
    missing_or_incorrect = []
    for attr_name, expected_value in required_attributes.items():
        current_value = current_attributes.get(attr_name, "").lower()
        if current_value != expected_value.lower():
            missing_or_incorrect.append(f"{attr_name}={expected_value}")
            logger.warning(f"[{lom}] Attribute {attr_name} is '{current_value}', expected '{expected_value}'")
    
    # If any attributes are missing or incorrect, set them
    if missing_or_incorrect:
        logger.info(f"[{lom}] Setting missing/incorrect attributes: {', '.join(missing_or_incorrect)}")
        set_attr_cmd = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--nodes", lom] + missing_or_incorrect
        
        if not run_cmd(set_attr_cmd):
            logger.error(f"[{lom}] Failed to set node attributes: {', '.join(missing_or_incorrect)}")
            return False
        
        # Verify again
        logger.info(f"[{lom}] Re-verifying attributes after setting")
        get_attr_cmd_verify = ["sudo", CHECKFIRMWARE_EXEC, "getattributes", "--nodes", lom]
        logger.info(f"[{lom}] Running verification command: {' '.join(get_attr_cmd_verify)}")
        attr_output = run_cmd(get_attr_cmd_verify)
        if attr_output:
            # Log the verification output
            logger.info(f"[{lom}] Verification getattributes output:\n{attr_output}")
            current_attributes = parse_attributes_output(attr_output)
            for attr_name, expected_value in required_attributes.items():
                current_value = current_attributes.get(attr_name, "").lower()
                if current_value != expected_value.lower():
                    logger.error(f"[{lom}] Attribute {attr_name} still incorrect after setting: '{current_value}' != '{expected_value}'")
                    return False
        else:
            logger.error(f"[{lom}] Failed to re-verify attributes")
            return False
    
    logger.info(f"[{lom}] All required node attributes are properly set")
    return True


def checkfirmware_service(lom: str, username: str, password: str, node_type: str, node_gen: str, deploy: bool, hostname: str = None) -> Dict:
    """Execute firmware check service for a node."""
    start_time = time.time()  # Track start time
    logger.info(f"Starting checkfirmware service for: {lom}, deploy={deploy}")
    result = {
        "node": lom,
        "status": None,
        "status_detail": None,  # Detailed node status for metadata
        "inventory_report": None,
        "deploy_status": None,
        "report_paths": None,
        "html_report_path": None,
        "html_report_url": None,  # HTTP URL to access the HTML report
        "checkfirmware_PRE_report": None,  # Pre-deployment report (only when deploy=True)
        "checkfirmware_report": None,  # Main report (post-deployment if deploy=True, standard if deploy=False)
        "checkfirmware_execution_time": None,  # Execution time in formatted string
        "success": False,
        "execution_time_seconds": 0.0,
        "execution_time_formatted": "0m 0s",
    }

    base_dir, reports_dir, temp_dir, timestamp = prepare_report_directories(lom)

    logger.info(f"[{lom}] Setting report_dir to {reports_dir}")
    if not run_cmd(["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--session", f"report_dir={reports_dir}"]):
        logger.error(f"[{lom}] Failed to set report_dir to {reports_dir}")
        exec_time, exec_time_str = calculate_execution_time(start_time)
        result.update({"status": "Failed to set report_dir", "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
        return result

    BASELINE_PATH = f"/pub/spp/{node_gen}_spp_current/packages"
    logger.info(f"[{lom}] Using BASELINE_PATH: {BASELINE_PATH}")

    output = get_node_status(lom)
    status = parse_node_status(output, lom) if output else None

    if status and "incorrect username/password" in status.lower():
        logger.info(f"[{lom}] Authentication failure detected, attempting to delete and re-add node")
        delete_cmd = ["sudo", CHECKFIRMWARE_EXEC, "delete", "--nodes", lom]
        if not run_cmd(delete_cmd):
            exec_time, exec_time_str = calculate_execution_time(start_time)
            result.update({"status": "Failed to delete node after authentication failure", "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
            return result
        
        # Re-add the node
        if not run_cmd([
                "sudo",
                CHECKFIRMWARE_EXEC,
                "add",
                "--nodes",
                lom,
                f"user={username}",
                f"password={shlex.quote(password)}",
                f"type={node_type}",
            ]):
            exec_time, exec_time_str = calculate_execution_time(start_time)
            result.update({"status": "Failed to re-add node after authentication failure", "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
            return result
        
        # IMMEDIATELY set attributes after node is added - BEFORE any other smartupdate commands
        logger.info(f"[{lom}] Setting attributes immediately after re-adding node")
        set_attr_cmd = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--nodes", lom, "ignore_warnings=true", "ignore_tmp=true", "on_failed_dependency=force", "skip_prereqs=true"]
        logger.info(f"[{lom}] Running setattributes command: {' '.join(set_attr_cmd)}")
        if not run_cmd(set_attr_cmd):
            logger.warning(f"[{lom}] Failed to set attributes immediately after re-adding node")
        else:
            logger.info(f"[{lom}] Successfully set attributes after re-adding node")
        
        # Immediately check what attributes were actually set
        logger.info(f"[{lom}] Checking attributes immediately after setting them")
        get_attr_cmd = ["sudo", CHECKFIRMWARE_EXEC, "getattributes", "--nodes", lom]
        logger.info(f"[{lom}] Running getattributes command: {' '.join(get_attr_cmd)}")
        attr_check_output = run_cmd(get_attr_cmd)
        if attr_check_output:
            logger.info(f"[{lom}] Immediate getattributes output after re-adding node:")
            logger.info(f"[{lom}] ATTRIBUTES START")
            logger.info(attr_check_output)
            logger.info(f"[{lom}] ATTRIBUTES END")
        else:
            logger.warning(f"[{lom}] Failed to get attributes immediately after setting them")
            
        # Verify attributes are properly set
        if not verify_and_set_node_attributes(lom):
            logger.error(f"[{lom}] Failed to verify/set required node attributes")
            
        # Now get status after attributes are set
        output = get_node_status(lom)
        status = parse_node_status(output, lom) if output else None

    if not status:
        logger.info(f"[{lom}] Node not found — attempting to add")
        if not run_cmd(
            [
                "sudo",
                CHECKFIRMWARE_EXEC,
                "add",
                "--nodes",
                lom,
                f"user={username}",
                f"password={shlex.quote(password)}",
                f"type={node_type}",
            ]
        ):
            exec_time, exec_time_str = calculate_execution_time(start_time)
            result.update({"status": "Failed to add node", "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
            return result
        
        # IMMEDIATELY set attributes after node is added - BEFORE any other smartupdate commands
        logger.info(f"[{lom}] Setting attributes immediately after adding new node")
        set_attr_cmd = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--nodes", lom, "ignore_warnings=true", "ignore_tmp=true", "on_failed_dependency=force", "skip_prereqs=true"]
        logger.info(f"[{lom}] Running setattributes command: {' '.join(set_attr_cmd)}")
        if not run_cmd(set_attr_cmd):
            logger.warning(f"[{lom}] Failed to set attributes immediately after adding new node")
        else:
            logger.info(f"[{lom}] Successfully set attributes after adding new node")
        
        # Immediately check what attributes were actually set
        logger.info(f"[{lom}] Checking attributes immediately after setting them")
        get_attr_cmd = ["sudo", CHECKFIRMWARE_EXEC, "getattributes", "--nodes", lom]
        logger.info(f"[{lom}] Running getattributes command: {' '.join(get_attr_cmd)}")
        attr_check_output = run_cmd(get_attr_cmd)
        if attr_check_output:
            logger.info(f"[{lom}] Immediate getattributes output after adding new node:")
            logger.info(f"[{lom}] ATTRIBUTES START")
            logger.info(attr_check_output)
            logger.info(f"[{lom}] ATTRIBUTES END")
        else:
            logger.warning(f"[{lom}] Failed to get attributes immediately after setting them")
            
        # Verify attributes are properly set
        if not verify_and_set_node_attributes(lom):
            logger.error(f"[{lom}] Failed to verify/set required node attributes")
            
        # Now get status after attributes are set
        output = get_node_status(lom)
        status = parse_node_status(output, lom) if output else None

    if status and "incorrect username/password" in status.lower():
        exec_time, exec_time_str = calculate_execution_time(start_time)
        result.update({"status": "Failed to authenticate node", "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
        return result

    inv_cmd = ["sudo", CHECKFIRMWARE_EXEC, "inventory", "--nodes", lom, "--baselines", BASELINE_PATH]
    inventory_report = run_cmd(inv_cmd)

    if inventory_report and wait_for_inventory_progress(lom):
        result["success"] = True
        logger.info(f"[{lom}] Inventory completed successfully")
    else:
        exec_time, exec_time_str = calculate_execution_time(start_time)
        result.update({"status": status or "Inventory timeout or failed", "inventory_report": inventory_report, "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
        return result

    report_paths = []
    # Generate only deploy preview CSV report using the new command format
    # This command generates only the CSV file with installable components information
    report_cmd = ["sudo", CHECKFIRMWARE_EXEC, "generatereports", "--type", "Installables", "--output", "csv", "--nodes", lom]
    report_output = run_cmd(report_cmd)

    if report_output:
        logger.info(f"[{lom}] Deploy preview CSV report generated successfully")
        # Log first few lines of output for debugging without overwhelming the log
        output_lines = report_output.strip().split('\n')
        if len(output_lines) > 3:
            logger.debug(f"[{lom}] Report output preview: {output_lines[0]}... ({len(output_lines)} lines total)")
        else:
            logger.debug(f"[{lom}] Report output: {report_output.strip()}")
            
        for path in parse_report_paths(report_output, lom):
            # For files, move them directly to reports_dir
            path_obj = Path(path)
            if path_obj.is_file():
                dest_path = Path(reports_dir) / path_obj.name
                if moved_path := move_and_set_permissions(str(path), str(dest_path), lom):
                    report_paths.append(moved_path)

    # Generate HTML report from deploy preview CSV generated by smartupdate generatereports --type Installables --output csv
    html_report_path = None
    html_report_url = None
    if result["success"] and report_paths:
        # Calculate run time so far (this is for pre-deployment report)
        _, current_execution_time_formatted = calculate_execution_time(start_time)
        
        # Determine if update is required based on node status
        update_required = status and ("update required" in status.lower() or "update" in status.lower())
        
        html_report_path = generate_html_report(lom, reports_dir, base_dir, node_gen, BASELINE_PATH, 
                                               run_time=current_execution_time_formatted, 
                                               update_required=update_required)
        if html_report_path:
            html_report_url = generate_http_url(html_report_path)
            if html_report_url:
                logger.info(f"[{lom}] Generated HTTP URL for report access: {html_report_url}")
                
            # Set PRE report if this is a deployment, otherwise set as main report
            if deploy:
                result["checkfirmware_PRE_report"] = html_report_url
                logger.info(f"[{lom}] Set pre-deployment report URL: {html_report_url}")
            else:
                result["checkfirmware_report"] = html_report_url
                logger.info(f"[{lom}] Set main report URL: {html_report_url}")

    # Capture final node status for detailed reporting
    final_output = get_node_status(lom)
    final_status = parse_node_status(final_output, lom) if final_output else None

    # Ensure final directory permissions are set correctly
    try:
        subprocess.run(["sudo", "chmod", "-R", "755", base_dir], check=True)
        logger.info(f"[{lom}] Final permission check completed for {base_dir}")
    except subprocess.CalledProcessError as e:
        logger.warning(f"[{lom}] Failed to set final directory permissions: {e.stderr}")

    # Remove temporary directory (no longer needed since we're writing directly to reports_dir)
    try:
        subprocess.run(["sudo", "rm", "-rf", temp_dir], check=True)
        logger.info(f"[{lom}] Removed temporary report directory: {temp_dir}")
    except subprocess.CalledProcessError as e:
        logger.error(f"[{lom}] Failed to remove temporary report directory {temp_dir}: {e.stderr}")

    if deploy and result["success"]:
        # Verify node attributes before deployment
        logger.info(f"[{lom}] Verifying node attributes before deployment")
        if not verify_and_set_node_attributes(lom):
            logger.error(f"[{lom}] Node attributes verification failed, proceeding anyway")
        
        # Ensure server is powered on before firmware deployment
        try:
            logger.info(f"[{lom}] Ensuring server is powered on before firmware deployment")
            # Use hostname for ZTP Actions if provided, otherwise fall back to lom
            ztp_target = hostname if hostname else lom
            logger.info(f"[{lom}] Using ZTP target: {ztp_target}")
            
            # Use the existing ZTP pattern - just pass the hostname as a string
            # ZTP.Actions can handle a hostname string and will fetch network data
            server_action = ZTP.Actions(ztp_target)
            
            # Check power using ztp_power_off pattern but for getting status
            if hasattr(server_action, 'hardware') and server_action.hardware:
                if server_action.hardware == "dell":
                    from app.ZTP.dell import DellServer
                    myserver = DellServer(server_action.lomip, server_action.lomuser, server_action.lompass)
                elif "hp" in server_action.hardware:
                    from app.ZTP.hphpe import HpHpeServer
                    myserver = HpHpeServer(server_action.lomip, server_action.lomuser, server_action.lompass)
                else:
                    logger.warning(f"[{lom}] Unknown hardware type: {server_action.hardware}")
                    myserver = None
                
                if myserver:
                    power_status = myserver.get_power_status()
                    logger.info(f"[{lom}] Current power status: {power_status}")
                    
                    if power_status.lower() != "on":
                        logger.info(f"[{lom}] Server is {power_status}, powering on before deployment")
                        myserver.set_power_on()
                        # Wait longer for server to fully boot and stabilize
                        logger.info(f"[{lom}] Waiting 60 seconds for server to fully power on and stabilize")
                        time.sleep(60)
                        
                        # Verify power is on and stable
                        for attempt in range(3):
                            new_power_status = myserver.get_power_status()
                            logger.info(f"[{lom}] Power status check {attempt + 1}/3: {new_power_status}")
                            if new_power_status.lower() == "on":
                                break
                            time.sleep(20)
                        
                        logger.info(f"[{lom}] Final power status after power-on: {new_power_status}")
                    else:
                        logger.info(f"[{lom}] Server is already powered on")
                        # Even if already on, wait a bit to ensure SmartUpdate Manager recognizes it
                        logger.info(f"[{lom}] Waiting 10 seconds for SmartUpdate Manager to recognize power state")
                        time.sleep(10)
                    del myserver
            else:
                logger.warning(f"[{lom}] Could not determine hardware type for power management")
                
        except Exception as e:
            logger.warning(f"[{lom}] Could not manage server power: {e}")
            logger.warning(f"[{lom}] Proceeding with deployment anyway")
        
        dep_cmd = ["sudo", CHECKFIRMWARE_EXEC, "deploy", "--nodes", lom]
        logger.info(f"[{lom}] Starting firmware deployment with command: {' '.join(dep_cmd)}")
        deploy_result = run_cmd(dep_cmd, return_dict=True)
        result["deploy_status"] = deploy_result
        
        # Log detailed deployment results
        if deploy_result and deploy_result.get("success"):
            logger.info(f"[{lom}] Firmware deployment command completed successfully")
            if deploy_result.get("output"):
                logger.info(f"[{lom}] Deployment output: {deploy_result['output']}")
            
            # Wait for deployment to complete by monitoring node status
            logger.info(f"[{lom}] Monitoring deployment progress...")
            deployment_completed = wait_for_deployment_progress(lom)
            
            if deployment_completed:
                logger.info(f"[{lom}] Deployment monitoring completed")
                # Get final deployment status
                final_deploy_output = get_node_status(lom)
                final_deploy_status = parse_node_status(final_deploy_output, lom) if final_deploy_output else None
                
                if final_deploy_status:
                    logger.info(f"[{lom}] Final deployment status: {final_deploy_status}")
                    result["final_deploy_status"] = final_deploy_status
                    
                    # Check if deployment was successful based on final status
                    if any(keyword in final_deploy_status.lower() for keyword in ["success", "completed", "up to date", "current"]):
                        logger.info(f"[{lom}] Deployment appears successful based on final status")
                        result["deploy_monitoring_success"] = True
                    elif any(keyword in final_deploy_status.lower() for keyword in ["failed", "error", "timeout"]):
                        logger.warning(f"[{lom}] Deployment may have failed based on final status")
                        result["deploy_monitoring_success"] = False
                    else:
                        logger.info(f"[{lom}] Deployment status unclear, proceeding with post-deployment inventory")
                        result["deploy_monitoring_success"] = True  # Assume success for now
                else:
                    logger.warning(f"[{lom}] Could not get final deployment status")
                    result["deploy_monitoring_success"] = True  # Assume success for now
            else:
                logger.warning(f"[{lom}] Deployment monitoring timed out, but proceeding with post-deployment steps")
                result["deploy_monitoring_success"] = False
                
        else:
            logger.error(f"[{lom}] Firmware deployment command failed")
            if deploy_result and deploy_result.get("error"):
                logger.error(f"[{lom}] Deployment error: {deploy_result['error']}")
            if deploy_result and deploy_result.get("output"):
                logger.error(f"[{lom}] Deployment output: {deploy_result['output']}")
            result["deploy_monitoring_success"] = False

        # If deployment was successful, rerun inventory and generate updated reports
        if deploy_result and deploy_result.get("success"):
            logger.info(f"[{lom}] Deployment command successful, running post-deployment inventory to get updated firmware status")
            
            # Run inventory again to get current firmware status
            post_deploy_inv_cmd = ["sudo", CHECKFIRMWARE_EXEC, "inventory", "--nodes", lom, "--baselines", BASELINE_PATH]
            post_deploy_inventory = run_cmd(post_deploy_inv_cmd)
            
            if post_deploy_inventory and wait_for_inventory_progress(lom):
                logger.info(f"[{lom}] Post-deployment inventory completed successfully")
                result["post_deploy_inventory"] = post_deploy_inventory
                
                # Generate updated reports
                logger.info(f"[{lom}] Generating updated reports after deployment")
                post_deploy_report_cmd = ["sudo", CHECKFIRMWARE_EXEC, "generatereports", "--type", "Installables", "--output", "csv", "--nodes", lom]
                post_deploy_report_output = run_cmd(post_deploy_report_cmd)
                
                if post_deploy_report_output:
                    logger.info(f"[{lom}] Post-deployment CSV report generated successfully")
                    
                    # Create a subdirectory for post-deployment reports
                    post_deploy_reports_dir = os.path.join(base_dir, "post_deploy_reports")
                    os.makedirs(post_deploy_reports_dir, exist_ok=True)
                    
                    post_deploy_report_paths = []
                    for path in parse_report_paths(post_deploy_report_output, lom):
                        path_obj = Path(path)
                        if path_obj.is_file():
                            dest_path = Path(post_deploy_reports_dir) / f"post_deploy_{path_obj.name}"
                            if moved_path := move_and_set_permissions(str(path), str(dest_path), lom):
                                post_deploy_report_paths.append(moved_path)
                    
                    # Generate updated HTML report
                    if post_deploy_report_paths:
                        # Calculate run time for post-deployment report
                        _, post_deploy_execution_time_formatted = calculate_execution_time(start_time)
                        
                        # Check post-deployment status to determine if more updates are needed
                        final_deploy_output = get_node_status(lom)
                        final_deploy_status = parse_node_status(final_deploy_output, lom) if final_deploy_output else None
                        post_deploy_update_required = final_deploy_status and ("update required" in final_deploy_status.lower() or "update" in final_deploy_status.lower())
                        
                        post_deploy_html_path = generate_html_report(lom, post_deploy_reports_dir, base_dir, node_gen, BASELINE_PATH,
                                                                   run_time=post_deploy_execution_time_formatted,
                                                                   update_required=post_deploy_update_required)
                        if post_deploy_html_path:
                            # Rename to indicate it's post-deployment
                            html_filename = Path(post_deploy_html_path).name
                            post_deploy_html_filename = f"post_deploy_{html_filename}"
                            final_post_deploy_html_path = os.path.join(base_dir, post_deploy_html_filename)
                            subprocess.run(["sudo", "mv", post_deploy_html_path, final_post_deploy_html_path], check=True)
                            set_readable_permissions(final_post_deploy_html_path, lom)
                            
                            post_deploy_html_url = generate_http_url(final_post_deploy_html_path)
                            
                            result["post_deploy_report_paths"] = post_deploy_report_paths
                            result["post_deploy_html_report_path"] = final_post_deploy_html_path
                            result["post_deploy_html_report_url"] = post_deploy_html_url
                            result["checkfirmware_report"] = post_deploy_html_url  # Set as main report for deployment
                            
                            logger.info(f"[{lom}] Generated post-deployment HTML report: {final_post_deploy_html_path}")
                            if post_deploy_html_url:
                                logger.info(f"[{lom}] Post-deployment report URL: {post_deploy_html_url}")
                                logger.info(f"[{lom}] Set main checkfirmware_report to post-deployment report")
                    
                    # Set permissions for post-deployment reports directory
                    subprocess.run(["sudo", "chmod", "-R", "755", post_deploy_reports_dir], check=True)
                else:
                    logger.warning(f"[{lom}] Failed to generate post-deployment reports")
            else:
                logger.warning(f"[{lom}] Post-deployment inventory failed or timed out")

    # Calculate execution time
    execution_time_seconds, execution_time_formatted = calculate_execution_time(start_time)
    
    result.update(
        {
            "status": status,
            "status_detail": final_status or status,  # Use final status if available, fallback to original
            "inventory_report": inventory_report,
            "report_paths": report_paths if report_paths else None,
            "html_report_path": html_report_path,
            "html_report_url": html_report_url,  # HTTP URL for web access
            "checkfirmware_execution_time": execution_time_formatted,  # Formatted execution time
            "success": result["success"] and bool(report_paths),
            "execution_time_seconds": execution_time_seconds,
            "execution_time_formatted": execution_time_formatted,
        }
    )
    
    logger.info(f"[{lom}] Checkfirmware service completed in {execution_time_formatted}")
    return result
