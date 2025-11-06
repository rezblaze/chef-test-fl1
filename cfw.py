This code works, but seems complicted. PLease refactor without breaking the current code. If the Node Status is not clean on neededing an update just report the node status and stop. Also before the deploy make sure the attributes and correctly segt and logged. 


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
REPORT_BASE_PATH = "/pub/reports/sum"

# Node attributes required for deployment
NODE_ATTRIBUTES_SET = {
    "ignore_warnings": "true",
    "ignore_tpm": "true", 
    "action": "ifneeded",
    "skip_prereqs": "true",
    "rewrite": "true"
}

# Expected values when verifying (SmartUpdate Manager may format them differently)
NODE_ATTRIBUTES_VERIFY = {
    "ignore_warnings": "true",
    "ignore_tpm": "true", 
    "action": "If Needed",
    "skip_prereqs": "true",
    "rewrite": "true"
}

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
    """Retrieve node status using 'getnodes <node_name> --details'."""
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "getnodes", lom, "--details"]
    output = run_cmd(cmd)
    if output:
        logger.debug(f"[{lom}] Retrieved getnodes --details output successfully")
        return output
    logger.warning(f"[{lom}] Failed to retrieve getnodes --details output")
    return None


def wait_for_process_completion(lom: str, process_name: str, in_progress_keywords: List[str], max_minutes: int = 30) -> bool:
    """Generic function to wait for any process (inventory/deployment) to complete.
    
    Args:
        lom: Node name
        process_name: Human-readable process name for logging
        in_progress_keywords: List of keywords that indicate process is still running
        max_minutes: Maximum time to wait in minutes
    
    Returns:
        bool: True if process completed, False if timed out
    """
    check_interval = 30  # Check every 30 seconds
    max_attempts = (max_minutes * 60) // check_interval
    
    logger.info(f"[{lom}] Starting {process_name} monitoring (checking every {check_interval} seconds)")
    
    previous_status = None
    for attempt in range(max_attempts):
        output = get_node_status(lom)
        status = parse_node_status(output, lom) if output else None
        
        elapsed_seconds = (attempt + 1) * check_interval
        elapsed_minutes = elapsed_seconds // 60
        elapsed_secs = elapsed_seconds % 60
        
        if status:
            status_changed = status != previous_status
            log_periodic = (attempt + 1) % 4 == 0  # Every 2 minutes
            
            if status_changed:
                logger.info(f"[{lom}] Status changed to: '{status}' (elapsed: {elapsed_minutes}m {elapsed_secs}s)")
            elif log_periodic:
                logger.info(f"[{lom}] Status check: '{status}' (elapsed: {elapsed_minutes}m {elapsed_secs}s / {max_minutes}m)")
            
            # For deployment processes, log complete getnodes output every 30 seconds for detailed tracking
            if "deployment" in process_name.lower():
                logger.info(f"[{lom}] Complete getnodes output (elapsed: {elapsed_minutes}m {elapsed_secs}s):")
                for line in output.strip().split('\n'):
                    logger.info(f"[{lom}] DEPLOY: {line}")
            
            # Check if process is still in progress
            status_lower = status.lower()
            if any(keyword in status_lower for keyword in in_progress_keywords):
                if status_changed:
                    logger.info(f"[{lom}] {process_name} in progress...")
            else:
                logger.info(f"[{lom}] {process_name} completed after {elapsed_minutes}m {elapsed_secs}s - Final Status: {status}")
                return True
                
            previous_status = status
        else:
            logger.warning(f"[{lom}] No status retrieved on attempt {attempt + 1}/{max_attempts}")
        
        if attempt < max_attempts - 1:
            time.sleep(check_interval)
    
    logger.error(f"[{lom}] {process_name} did not complete after {max_minutes} minutes - timed out")
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
    if not output:
        return attributes
    
    lines = output.strip().split("\n")
    current_section = None
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
            
        # Check for section headers
        if line.endswith(":") and not any(char in line for char in ["=", "\t"]):
            current_section = line[:-1].strip()
            continue
            
        # Parse attribute lines with various separators
        if ":" in line:
            # Handle lines like "action          : Never" or "ignore_warnings: true"
            parts = line.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                attributes[key] = value
        elif "\t" in line:
            # Handle lines with tabs like "rewrite			: false"
            parts = line.split(":", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                attributes[key] = value
        elif "=" in line:
            # Handle lines like "attribute=value"
            parts = line.split("=", 1)
            if len(parts) == 2:
                key = parts[0].strip()
                value = parts[1].strip()
                attributes[key] = value
    
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


def generate_html_report(lom: str, reports_dir: str, base_dir: str, node_gen: str = None, baseline_path: str = None, run_time: str = None, update_required: bool = None, current_node_status: str = None, post_deploy_report_url: str = None) -> Optional[str]:
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
        html_output = parse_sum_report_to_html(csv_content, server_name=lom, node_gen=node_gen, baseline_path=baseline_path, run_time=run_time, update_required=update_required, current_node_status=current_node_status, post_deploy_report_url=post_deploy_report_url)
        
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


def is_node_up_to_date(lom: str) -> bool:
    """Check if node is up to date (no firmware updates required)."""
    output = get_node_status(lom)
    status = parse_node_status(output, lom) if output else None
    
    if not status:
        logger.warning(f"[{lom}] Could not determine node status")
        return False
    
    status_lower = status.lower()
    needs_update = any(keyword in status_lower for keyword in ["update required", "update"])
    
    if needs_update:
        logger.info(f"[{lom}] Node requires updates - Status: {status}")
        return False
    else:
        logger.info(f"[{lom}] Node appears up to date - Status: {status}")
        return True


def perform_deployment_with_retry(lom: str, hostname: str = None) -> Dict:
    """Perform deployment and retry once if node is not up to date."""
    deployment_result = {
        "initial_deploy_success": False,
        "final_status": None,
        "retry_attempted": False,
        "retry_deploy_success": False,
        "overall_success": False
    }
    
    # Verify node attributes before deployment
    logger.info(f"[{lom}] Verifying node attributes before deployment")
    if not verify_and_set_node_attributes(lom):
        logger.error(f"[{lom}] Node attributes verification failed, proceeding anyway")
    
    # Ensure server is powered on before firmware deployment
    logger.info(f"[{lom}] Ensuring server is powered on before firmware deployment")
    ensure_server_powered_on(lom, hostname)
    
    # First deployment attempt
    dep_cmd = ["sudo", CHECKFIRMWARE_EXEC, "deploy", "--nodes", lom]
    logger.info(f"[{lom}] Starting initial firmware deployment with command: {' '.join(dep_cmd)}")
    deploy_result = run_cmd(dep_cmd, return_dict=True)
    
    if deploy_result and deploy_result.get("success"):
        logger.info(f"[{lom}] Initial deployment command completed successfully")
        deployment_result["initial_deploy_success"] = True
        
        # Wait for deployment to complete
        deployment_completed = wait_for_process_completion(lom, "Initial Deployment", 
            ["deploy started", "deploying", "deployment in progress", "installing", "updating", "rebooting", "reboot"], 60)
        
        if deployment_completed:
            logger.info(f"[{lom}] Initial deployment monitoring completed")
            
            # Check if node is up to date after first deployment
            if not is_node_up_to_date(lom):
                logger.info(f"[{lom}] Node still requires updates after initial deployment, attempting retry")
                deployment_result["retry_attempted"] = True
                
                # Second deployment attempt
                logger.info(f"[{lom}] Starting retry firmware deployment")
                retry_deploy_result = run_cmd(dep_cmd, return_dict=True)
                
                if retry_deploy_result and retry_deploy_result.get("success"):
                    logger.info(f"[{lom}] Retry deployment command completed successfully")
                    deployment_result["retry_deploy_success"] = True
                    
                    # Wait for retry deployment to complete
                    retry_completed = wait_for_process_completion(lom, "Retry Deployment", 
                        ["deploy started", "deploying", "deployment in progress", "installing", "updating", "rebooting", "reboot"], 60)
                    
                    if retry_completed:
                        logger.info(f"[{lom}] Retry deployment monitoring completed")
                else:
                    logger.error(f"[{lom}] Retry deployment command failed")
            else:
                logger.info(f"[{lom}] Node is up to date after initial deployment")
        else:
            logger.warning(f"[{lom}] Initial deployment monitoring timed out")
    else:
        logger.error(f"[{lom}] Initial deployment command failed")
    
    # Get final status
    final_output = get_node_status(lom)
    final_status = parse_node_status(final_output, lom) if final_output else None
    deployment_result["final_status"] = final_status
    deployment_result["overall_success"] = is_node_up_to_date(lom)
    
    logger.info(f"[{lom}] Deployment summary - Initial: {deployment_result['initial_deploy_success']}, "
                f"Retry: {deployment_result['retry_attempted']}, Final Status: {final_status}")
    
    return deployment_result


def set_session_attributes(reports_dir: str, lom: str) -> bool:
    """Set session-level attributes for SmartUpdate Manager."""
    logger.info(f"[{lom}] Setting session attribute: report_dir={reports_dir}")
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--session", f"report_dir={reports_dir}"]
    
    if run_cmd(cmd):
        logger.info(f"[{lom}] Successfully set session attributes")
        return True
    else:
        logger.error(f"[{lom}] Failed to set session attributes")
        return False


def set_node_attributes(lom: str) -> bool:
    """Set all required node attributes for deployment."""
    # Convert dictionary to list of command-line formatted strings
    attributes = [f"{key}={value}" for key, value in NODE_ATTRIBUTES_SET.items()]
    
    logger.info(f"[{lom}] Setting node attributes: {', '.join(attributes)}")
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--nodes", lom] + attributes
    
    result = run_cmd(cmd)
    if not result:
        logger.error(f"[{lom}] Failed to set node attributes")
        return False
    
    logger.info(f"[{lom}] Node attributes command completed, verifying they were applied correctly")
    
    # Wait a moment for attributes to be applied
    time.sleep(2)
    
    # Verify the attributes were actually set
    if not verify_node_attributes_applied(lom):
        logger.error(f"[{lom}] Node attributes verification failed after setting")
        return False
    
    logger.info(f"[{lom}] Successfully set and verified all node attributes")
    return True


def verify_node_attributes_applied(lom: str) -> bool:
    """Verify that all required node attributes are properly applied."""
    logger.info(f"[{lom}] Verifying node attributes are properly applied")
    attr_output = run_cmd(["sudo", CHECKFIRMWARE_EXEC, "getattributes", "--nodes", lom])
    
    if not attr_output:
        logger.error(f"[{lom}] Failed to get node attributes for verification")
        return False
    
    # Log the complete getattributes output to the log file
    logger.info(f"[{lom}] Complete getattributes output:")
    for line in attr_output.strip().split('\n'):
        logger.info(f"[{lom}] ATTR: {line}")
    
    # Parse and check attributes
    current_attributes = parse_attributes_output(attr_output)
    logger.info(f"[{lom}] Parsed attributes: {current_attributes}")
    
    failed_attributes = []
    
    for attr_name, expected_value in NODE_ATTRIBUTES_VERIFY.items():
        current_value = current_attributes.get(attr_name, "").lower()
        expected_lower = expected_value.lower()
        
        if current_value != expected_lower:
            failed_attributes.append(f"{attr_name}: expected '{expected_value}', got '{current_value}'")
    
    if failed_attributes:
        logger.error(f"[{lom}] Node attributes verification failed:")
        for failed_attr in failed_attributes:
            logger.error(f"[{lom}]   - {failed_attr}")
        return False
    
    logger.info(f"[{lom}] All required node attributes are properly applied and verified")
    return True


def set_node_attributes_with_retry(lom: str, max_retries: int = 3) -> bool:
    """Set node attributes with retry logic to ensure they are properly applied."""
    for attempt in range(max_retries):
        logger.info(f"[{lom}] Setting node attributes - attempt {attempt + 1}/{max_retries}")
        
        if set_node_attributes(lom):
            logger.info(f"[{lom}] Node attributes successfully set and verified on attempt {attempt + 1}")
            return True
        
        if attempt < max_retries - 1:
            logger.warning(f"[{lom}] Node attributes failed on attempt {attempt + 1}, retrying...")
            time.sleep(5)  # Wait before retry
        else:
            logger.error(f"[{lom}] Node attributes failed after {max_retries} attempts")
    
    return False


def ensure_server_powered_on(lom: str, hostname: str = None) -> bool:
    """Ensure server is powered on before firmware deployment."""
    try:
        ztp_target = hostname if hostname else lom
        logger.info(f"[{lom}] Checking power status using ZTP target: {ztp_target}")
        
        server_action = ZTP.Actions(ztp_target)
        
        if not (hasattr(server_action, 'hardware') and server_action.hardware and "hp" in server_action.hardware):
            logger.warning(f"[{lom}] Not an HP/HPE system or hardware type unknown: {getattr(server_action, 'hardware', 'Unknown')}")
            return False
            
        from app.ZTP.hphpe import HpHpeServer
        myserver = HpHpeServer(server_action.lomip, server_action.lomuser, server_action.lompass)
        
        power_status = myserver.get_power_status()
        logger.info(f"[{lom}] Current power status: {power_status}")
        
        if power_status.lower() != "on":
            logger.info(f"[{lom}] Server is {power_status}, powering on")
            myserver.set_power_on()
            logger.info(f"[{lom}] Waiting 60 seconds for server to stabilize")
            time.sleep(60)
            
            # Verify power status
            new_power_status = myserver.get_power_status()
            logger.info(f"[{lom}] Power status after power-on: {new_power_status}")
        else:
            logger.info(f"[{lom}] Server is already powered on")
            time.sleep(10)  # Brief wait for SmartUpdate Manager
            
        del myserver
        return True
        
    except Exception as e:
        logger.warning(f"[{lom}] Could not manage server power: {e}")
        return False


def clean_add_node_with_attributes(lom: str, username: str, password: str, node_type: str) -> bool:
    """Remove node if exists, then add node (attributes set separately)."""
    logger.info(f"[{lom}] Performing clean node addition (remove if exists, then add)")
    
    # Always attempt to remove the node first (ignore failures)
    logger.info(f"[{lom}] Removing node if it exists")
    run_cmd(["sudo", CHECKFIRMWARE_EXEC, "delete", "--nodes", lom])
    
    # Add the node
    logger.info(f"[{lom}] Adding node")
    if not run_cmd([
        "sudo", CHECKFIRMWARE_EXEC, "add", "--nodes", lom,
        f"user={username}", f"password={shlex.quote(password)}", f"type={node_type}"
    ]):
        logger.error(f"[{lom}] Failed to add node")
        return False
    
    logger.info(f"[{lom}] Node added successfully")
    return True


def add_node_with_attributes(lom: str, username: str, password: str, node_type: str) -> bool:
    """Add a node and immediately set required attributes."""
    # Add the node
    if not run_cmd([
        "sudo", CHECKFIRMWARE_EXEC, "add", "--nodes", lom,
        f"user={username}", f"password={shlex.quote(password)}", f"type={node_type}"
    ]):
        return False
    
    # Set attributes immediately after adding
    return set_node_attributes(lom)


def verify_and_set_node_attributes(lom: str) -> bool:
    """Verify and ensure node attributes are properly set for deployment."""
    # Get current attributes
    logger.info(f"[{lom}] Verifying node attributes before deployment")
    attr_output = run_cmd(["sudo", CHECKFIRMWARE_EXEC, "getattributes", "--nodes", lom])
    
    if not attr_output:
        logger.warning(f"[{lom}] Failed to get node attributes, attempting to set them anyway")
        return set_node_attributes_with_retry(lom)
    
    # Log the complete getattributes output to the log file
    logger.info(f"[{lom}] Current getattributes output before deployment:")
    for line in attr_output.strip().split('\n'):
        logger.info(f"[{lom}] ATTR: {line}")
    
    # Parse and check attributes
    current_attributes = parse_attributes_output(attr_output)
    missing_or_incorrect = []
    
    for attr_name, expected_value in NODE_ATTRIBUTES_VERIFY.items():
        current_value = current_attributes.get(attr_name, "").lower()
        expected_lower = expected_value.lower()
        
        if current_value != expected_lower:
            missing_or_incorrect.append(f"{attr_name}={NODE_ATTRIBUTES_SET[attr_name]}")
    
    # Set any missing/incorrect attributes
    if missing_or_incorrect:
        logger.info(f"[{lom}] Setting missing attributes: {', '.join(missing_or_incorrect)}")
        cmd = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--nodes", lom] + missing_or_incorrect
        return bool(run_cmd(cmd))
    
    logger.info(f"[{lom}] All required node attributes are properly set")
    return True


def checkfirmware_service(lom: str, username: str, password: str, node_type: str, node_gen: str, deploy: bool, hostname: str = None) -> Dict:
    """Execute firmware check service for a node following the specified workflow."""
    start_time = time.time()
    logger.info(f"Starting checkfirmware service for: {lom}, deploy={deploy}")
    
    result = {
        "node": lom,
        "status": None,
        "status_detail": None,
        "inventory_report": None,
        "deploy_status": None,
        "report_paths": None,
        "html_report_path": None,
        "html_report_url": None,
        "checkfirmware_PRE_report": None,
        "checkfirmware_report": None,
        "checkfirmware_execution_time": None,
        "success": False,
        "execution_time_seconds": 0.0,
        "execution_time_formatted": "0m 0s",
    }

    # Step 1: Prepare report directories
    base_dir, reports_dir, temp_dir, timestamp = prepare_report_directories(lom)
    BASELINE_PATH = f"/pub/spp/{node_gen}_spp_current/packages"
    logger.info(f"[{lom}] Using BASELINE_PATH: {BASELINE_PATH}")

    # Step 2: Check current node status (with --details)
    logger.info(f"[{lom}] Checking current node status with details")
    output = get_node_status(lom)
    initial_status = parse_node_status(output, lom) if output else None
    if initial_status:
        logger.info(f"[{lom}] Initial node status: {initial_status}")

    # Step 3: Clean node management - always remove then re-add
    logger.info(f"[{lom}] Performing clean node management (remove + add)")
    if not clean_add_node_with_attributes(lom, username, password, node_type):
        exec_time, exec_time_str = calculate_execution_time(start_time)
        result.update({"status": "Failed to clean add node", "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
        return result

    # Step 4: Set node attributes (CRITICAL - nothing proceeds if this fails)
    logger.info(f"[{lom}] Setting node attributes (CRITICAL STEP)")
    if not set_node_attributes_with_retry(lom, max_retries=3):
        exec_time, exec_time_str = calculate_execution_time(start_time)
        result.update({"status": "CRITICAL FAILURE: Failed to set node attributes after retries", "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
        logger.critical(f"[{lom}] STOPPING EXECUTION - Node attributes could not be set properly")
        return result

    # Step 5: Set session attributes
    logger.info(f"[{lom}] Setting session attributes")
    if not set_session_attributes(reports_dir, lom):
        exec_time, exec_time_str = calculate_execution_time(start_time)
        result.update({"status": "Failed to set session attributes", "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
        return result

    # Step 6: Run inventory
    logger.info(f"[{lom}] Running inventory")
    inv_cmd = ["sudo", CHECKFIRMWARE_EXEC, "inventory", "--nodes", lom, "--baselines", BASELINE_PATH]
    inventory_report = run_cmd(inv_cmd)

    if inventory_report and wait_for_process_completion(lom, "Inventory", ["inventory started"], 30):
        result["success"] = True
        logger.info(f"[{lom}] Inventory completed successfully")
    else:
        exec_time, exec_time_str = calculate_execution_time(start_time)
        result.update({"status": "Inventory timeout or failed", "inventory_report": inventory_report, "execution_time_seconds": exec_time, "execution_time_formatted": exec_time_str})
        return result

    # Step 7: Generate reports and HTML page
    logger.info(f"[{lom}] Generating reports")
    report_paths = []
    report_cmd = ["sudo", CHECKFIRMWARE_EXEC, "generatereports", "--type", "Installables", "--output", "csv", "--nodes", lom]
    report_output = run_cmd(report_cmd)

    if report_output:
        logger.info(f"[{lom}] Deploy preview CSV report generated successfully")
        for path in parse_report_paths(report_output, lom):
            path_obj = Path(path)
            if path_obj.is_file():
                dest_path = Path(reports_dir) / path_obj.name
                if moved_path := move_and_set_permissions(str(path), str(dest_path), lom):
                    report_paths.append(moved_path)

    # Step 8: Create HTML page
    html_report_path = None
    html_report_url = None
    if result["success"] and report_paths:
        _, current_execution_time_formatted = calculate_execution_time(start_time)
        
        # Get current status to determine if update is required
        current_output = get_node_status(lom)
        current_status = parse_node_status(current_output, lom) if current_output else None
        update_required = current_status and ("update required" in current_status.lower() or "update" in current_status.lower())
        
        html_report_path = generate_html_report(lom, reports_dir, base_dir, node_gen, BASELINE_PATH, 
                                               run_time=current_execution_time_formatted, 
                                               update_required=update_required, current_node_status=current_status)
        if html_report_path:
            html_report_url = generate_http_url(html_report_path)
            if html_report_url:
                logger.info(f"[{lom}] Generated HTTP URL for report access: {html_report_url}")
                
            if deploy:
                result["checkfirmware_PRE_report"] = html_report_url
                logger.info(f"[{lom}] Set pre-deployment report URL: {html_report_url}")
            else:
                result["checkfirmware_report"] = html_report_url
                logger.info(f"[{lom}] Set main report URL: {html_report_url}")

    # Step 9: Ensure reports are in correct location with proper permissions
    logger.info(f"[{lom}] Ensuring proper report permissions")
    try:
        subprocess.run(["sudo", "chmod", "-R", "755", base_dir], check=True)
        logger.info(f"[{lom}] Set proper permissions for {base_dir}")
    except subprocess.CalledProcessError as e:
        logger.warning(f"[{lom}] Failed to set directory permissions: {e.stderr}")

    # Remove temporary directory
    try:
        subprocess.run(["sudo", "rm", "-rf", temp_dir], check=True)
        logger.info(f"[{lom}] Removed temporary report directory: {temp_dir}")
    except subprocess.CalledProcessError as e:
        logger.error(f"[{lom}] Failed to remove temporary report directory {temp_dir}: {e.stderr}")

    # Step 10: If deploy=True, perform deployment workflow
    if deploy and result["success"]:
        logger.info(f"[{lom}] Starting deployment workflow")
        
        # Perform deployment with retry logic
        deployment_result = perform_deployment_with_retry(lom, hostname)
        result["deploy_status"] = deployment_result
        
        # Generate post-deployment reports if deployment was successful
        if deployment_result.get("overall_success"):
            logger.info(f"[{lom}] Deployment successful, generating post-deployment reports")
            
            # Run post-deployment inventory
            post_deploy_inv_cmd = ["sudo", CHECKFIRMWARE_EXEC, "inventory", "--nodes", lom, "--baselines", BASELINE_PATH]
            post_deploy_inventory = run_cmd(post_deploy_inv_cmd)
            
            if post_deploy_inventory and wait_for_process_completion(lom, "Post-deployment inventory", ["inventory started"], 30):
                logger.info(f"[{lom}] Post-deployment inventory completed successfully")
                result["post_deploy_inventory"] = post_deploy_inventory
                
                # Generate updated reports
                post_deploy_report_cmd = ["sudo", CHECKFIRMWARE_EXEC, "generatereports", "--type", "Installables", "--output", "csv", "--nodes", lom]
                post_deploy_report_output = run_cmd(post_deploy_report_cmd)
                
                if post_deploy_report_output:
                    logger.info(f"[{lom}] Post-deployment CSV report generated successfully")
                    
                    # Create subdirectory for post-deployment reports
                    post_deploy_reports_dir = os.path.join(base_dir, "post_deploy_reports")
                    os.makedirs(post_deploy_reports_dir, exist_ok=True)
                    
                    post_deploy_report_paths = []
                    for path in parse_report_paths(post_deploy_report_output, lom):
                        path_obj = Path(path)
                        if path_obj.is_file():
                            dest_path = Path(post_deploy_reports_dir) / f"post_deploy_{path_obj.name}"
                            if moved_path := move_and_set_permissions(str(path), str(dest_path), lom):
                                post_deploy_report_paths.append(moved_path)
                    
                    # Generate post-deployment HTML report
                    if post_deploy_report_paths:
                        _, post_deploy_execution_time_formatted = calculate_execution_time(start_time)
                        
                        # Check final status
                        final_output = get_node_status(lom)
                        final_status = parse_node_status(final_output, lom) if final_output else None
                        post_deploy_update_required = final_status and ("update required" in final_status.lower() or "update" in final_status.lower())
                        
                        post_deploy_html_path = generate_html_report(lom, post_deploy_reports_dir, base_dir, node_gen, BASELINE_PATH,
                                                                   run_time=post_deploy_execution_time_formatted,
                                                                   update_required=post_deploy_update_required, current_node_status=final_status)
                        if post_deploy_html_path:
                            html_filename = Path(post_deploy_html_path).name
                            post_deploy_html_filename = f"post_deploy_{html_filename}"
                            final_post_deploy_html_path = os.path.join(base_dir, post_deploy_html_filename)
                            subprocess.run(["sudo", "mv", post_deploy_html_path, final_post_deploy_html_path], check=True)
                            set_readable_permissions(final_post_deploy_html_path, lom)
                            
                            post_deploy_html_url = generate_http_url(final_post_deploy_html_path)
                            result["post_deploy_html_report_url"] = post_deploy_html_url
                            result["checkfirmware_report"] = post_deploy_html_url  # Set as main report
                            
                            logger.info(f"[{lom}] Generated post-deployment HTML report: {final_post_deploy_html_path}")
                            if post_deploy_html_url:
                                logger.info(f"[{lom}] Post-deployment report URL: {post_deploy_html_url}")
                                
                                # Update the original pre-deployment report to include link to post-deployment report
                                if html_report_path and report_paths:
                                    logger.info(f"[{lom}] Updating original report with post-deployment link")
                                    try:
                                        # Get current values for the updated report
                                        _, updated_execution_time_formatted = calculate_execution_time(start_time)
                                        current_output_updated = get_node_status(lom)
                                        current_status_updated = parse_node_status(current_output_updated, lom) if current_output_updated else None
                                        update_required_updated = current_status_updated and ("update required" in current_status_updated.lower() or "update" in current_status_updated.lower())
                                        
                                        updated_html_report_path = generate_html_report(lom, reports_dir, base_dir, node_gen, BASELINE_PATH, 
                                                                                       run_time=updated_execution_time_formatted, 
                                                                                       update_required=update_required_updated, current_node_status=current_status_updated,
                                                                                       post_deploy_report_url=post_deploy_html_url)
                                        if updated_html_report_path:
                                            logger.info(f"[{lom}] Successfully updated original report with post-deployment link")
                                        else:
                                            logger.warning(f"[{lom}] Failed to update original report with post-deployment link")
                                    except Exception as e:
                                        logger.error(f"[{lom}] Error updating original report: {e}")
                    
                    # Set permissions for post-deployment reports
                    subprocess.run(["sudo", "chmod", "-R", "755", post_deploy_reports_dir], check=True)
            else:
                logger.warning(f"[{lom}] Post-deployment inventory failed or timed out")

    # Get final status for result
    final_output = get_node_status(lom)
    final_status = parse_node_status(final_output, lom) if final_output else None

    # Calculate execution time
    execution_time_seconds, execution_time_formatted = calculate_execution_time(start_time)
    
    result.update({
        "status": initial_status or final_status,
        "status_detail": final_status or initial_status,
        "inventory_report": inventory_report,
        "report_paths": report_paths if report_paths else None,
        "html_report_path": html_report_path,
        "html_report_url": html_report_url,
        "checkfirmware_execution_time": execution_time_formatted,
        "success": result["success"] and bool(report_paths),
        "execution_time_seconds": execution_time_seconds,
        "execution_time_formatted": execution_time_formatted,
    })
    
    logger.info(f"[{lom}] Checkfirmware service completed in {execution_time_formatted}")
    return result

