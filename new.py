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

# Import HTML report generator
from .sum_report_gen import parse_sum_report_to_html

# Import ZTP for power management
import app.ZTP as ZTP

# === CONFIGURATION ===
CHECKFIRMWARE_EXEC = "/usr/sbin/smartupdate"
REPORT_BASE_PATH = "/pub/reports/sum"
BASELINE_PATH_TEMPLATE = "/pub/spp/{node_gen}_spp_current/packages"
PERMISSION_DIR = "755"
PERMISSION_FILE = "644"
DEPLOY_CHECK_INTERVAL = 30  # seconds
MAX_DEPLOY_ATTEMPTS = 120   # 60 minutes
MAX_INVENTORY_ATTEMPTS = 30
INVENTORY_CHECK_INTERVAL = 60

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

_first_smartupdate_called = False


# === UTILS ===
def run_cmd(cmd: List[str], timeout: int = 1800, return_dict: bool = False) -> Optional[Dict]:
    """Run subprocess command with enhanced handling."""
    global _first_smartupdate_called
    is_smartupdate = len(cmd) >= 2 and cmd[1] == CHECKFIRMWARE_EXEC

    if is_smartupdate and not _first_smartupdate_called:
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=os.environ.copy(), stdin=subprocess.PIPE
            )
            output, error = process.communicate(input="YES\n", timeout=timeout)
            _first_smartupdate_called = True
            success = process.returncode == 0
            result = {"success": success, "output": output, "error": error, "returncode": process.returncode}
            if return_dict:
                return result
            return output if success else None
        except Exception as e:
            logger.error(f"Command failed: {' '.join(cmd)} | {e}")
            return {"success": False, "error": str(e)} if return_dict else None
    else:
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout, env=os.environ.copy())
            res = {"success": True, "output": result.stdout, "error": result.stderr, "returncode": result.returncode}
            return res if return_dict else result.stdout
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout: {' '.join(cmd)}")
            return {"success": False, "error": "timeout"} if return_dict else None
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed: {' '.join(cmd)} | {e.stderr}")
            return {"success": False, "output": e.stdout, "error": e.stderr, "returncode": e.returncode} if return_dict else None


def parse_node_status(output: str, lom: str) -> Optional[str]:
    """Parse Node Status from getnodes output."""
    if not output:
        return None
    for line in output.splitlines():
        if line.strip().startswith("Node Status:"):
            return line.split(":", 1)[1].strip()
    match = re.search(rf"{re.escape(lom)}.*?Node Status:\s*([^\n]+)", output, re.DOTALL)
    return match.group(1).strip() if match else None


def get_node_status(lom: str) -> Optional[str]:
    """Run getnodes --details and return status."""
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "getnodes", lom, "--details"]
    output = run_cmd(cmd)
    return parse_node_status(output, lom) if output else None


def wait_for_status(lom: str, target_states: List[str], interval: int, max_attempts: int, phase: str) -> bool:
    """Wait for node to reach any of target_states."""
    logger.info(f"[{lom}] Waiting for {phase} completion (max {max_attempts * interval // 60} min)")
    for i in range(max_attempts):
        status = get_node_status(lom)
        elapsed = (i + 1) * interval // 60
        if status and any(state.lower() in status.lower() for state in target_states):
            logger.info(f"[{lom}] {phase} complete after {elapsed} min | Status: {status}")
            return True
        logger.info(f"[{lom}] {phase} in progress... ({elapsed} min) | Status: {status or 'Unknown'}")
        if i < max_attempts - 1:
            time.sleep(interval)
    logger.error(f"[{lom}] {phase} timed out after {max_attempts * interval // 60} min")
    return False


def ensure_node_removed(lom: str) -> bool:
    """Remove node if exists."""
    logger.info(f"[{lom}] Ensuring node is removed")
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "delete", "--nodes", lom]
    result = run_cmd(cmd, return_dict=True)
    if result["success"] or "not found" in result.get("error", "").lower():
        logger.info(f"[{lom}] Node removed or not present")
        return True
    logger.error(f"[{lom}] Failed to remove node")
    return False


def add_node(lom: str, username: str, password: str, node_type: str) -> bool:
    """Add node with credentials."""
    logger.info(f"[{lom}] Adding node")
    cmd = [
        "sudo", CHECKFIRMWARE_EXEC, "add", "--nodes", lom,
        f"user={username}", f"password={shlex.quote(password)}", f"type={node_type}"
    ]
    return bool(run_cmd(cmd))


def set_node_attributes(lom: str) -> bool:
    """Set required node attributes."""
    attrs = [
        "ignore_warnings=true", "ignore_tpm=true",
        "on_failed_dependency=force", "skip_prereqs=true"
    ]
    logger.info(f"[{lom}] Setting node attributes")
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--nodes", lom] + attrs
    return bool(run_cmd(cmd))


def set_session_report_dir(reports_dir: str) -> bool:
    """Set session-level report directory."""
    logger.info(f"Setting session report_dir = {reports_dir}")
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--session", f"report_dir={reports_dir}"]
    return bool(run_cmd(cmd))


def run_inventory(lom: str, baseline_path: str) -> bool:
    """Run inventory and wait."""
    logger.info(f"[{lom}] Running inventory")
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "inventory", "--nodes", lom, "--baselines", baseline_path]
    if not run_cmd(cmd):
        return False
    return wait_for_status(
        lom, ["Inventory completed", "Update required", "Up to date"],
        INVENTORY_CHECK_INTERVAL, MAX_INVENTORY_ATTEMPTS, "Inventory"
    )

def generate_deploy_preview_report(lom: str, reports_dir: str) -> List[str]:
    """Generate Installables CSV report."""
    logger.info(f"[{lom}] Generating deploy preview report")
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "generatereports", "--type", "Installables", "--output", "csv", "--nodes", lom]
    output = run_cmd(cmd)
    if not output:
        return []

    paths = []
    for match in re.finditer(r"(/pub/reports/[^ \n]+\.csv)", output):
        src = match.group(1)
        if not Path(src).exists():
            logger.warning(f"[{lom}] Report {src} not found on filesystem")
            continue
        
        # Compute dest
        dest = os.path.join(reports_dir, Path(src).name)
        
        # Skip move if src == dest (already in correct location)
        if src != dest:
            try:
                subprocess.run(["sudo", "mv", src, dest], check=True)
                logger.debug(f"[{lom}] Report moved: {src} -> {dest}")
            except subprocess.CalledProcessError as e:
                logger.error(f"[{lom}] Failed to move {src} to {dest}: {e}")
                continue  # Skip this path on failure
        else:
            logger.debug(f"[{lom}] Report already in place: {src}")
        
        # Always set permissions on final path
        final_path = dest if src != dest else src
        try:
            subprocess.run(["sudo", "chmod", PERMISSION_FILE, final_path], check=True)
            paths.append(final_path)
            logger.debug(f"[{lom}] Permissions set on: {final_path}")
        except subprocess.CalledProcessError as e:
            logger.error(f"[{lom}] Failed to set permissions on {final_path}: {e}")
    
    logger.info(f"[{lom}] Generated {len(paths)} report(s)")
    return paths


def generate_html_report(lom: str, reports_dir: str, base_dir: str, node_gen: str, baseline_path: str, run_time: str, update_required: bool) -> Optional[str]:
    """Generate HTML from first CSV in reports_dir."""
    csv_files = glob.glob(os.path.join(reports_dir, "*.csv"))
    if not csv_files:
        logger.warning(f"[{lom}] No CSV report found in {reports_dir}")
        return None

    csv_file = csv_files[0]
    with open(csv_file, 'r', encoding='utf-8') as f:
        csv_content = f.read()

    html_content = parse_sum_report_to_html(
        csv_content, server_name=lom, node_gen=node_gen,
        baseline_path=baseline_path, run_time=run_time, update_required=update_required
    )

    html_name = f"{Path(csv_file).stem}.html"
    html_path = os.path.join(base_dir, html_name)
    with open(html_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

    subprocess.run(["sudo", "chmod", PERMISSION_FILE, html_path], check=True)
    logger.info(f"[{lom}] HTML report: {html_path}")
    return html_path


def ensure_power_on(lom: str, hostname: str) -> None:
    """Ensure server is powered on before deploy."""
    target = hostname or lom
    logger.info(f"[{lom}] Ensuring power on via ZTP: {target}")
    try:
        action = ZTP.Actions(target)
        if not action.hardware:
            return

        if "dell" in action.hardware.lower():
            from app.ZTP.dell import DellServer
            server = DellServer(action.lomip, action.lomuser, action.lompass)
        elif "hp" in action.hardware.lower():
            from app.ZTP.hphpe import HpHpeServer
            server = HpHpeServer(action.lomip, action.lomuser, action.lompass)
        else:
            return

        status = server.get_power_status()
        if status.lower() != "on":
            logger.info(f"[{lom}] Powering on...")
            server.set_power_on()
            time.sleep(60)
            for _ in range(3):
                if server.get_power_status().lower() == "on":
                    break
                time.sleep(20)
        else:
            time.sleep(10)
        del server
    except Exception as e:
        logger.warning(f"[{lom}] Power management failed: {e}")


def run_deploy(lom: str) -> bool:
    """Run deploy and wait."""
    logger.info(f"[{lom}] Starting firmware deployment")
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "deploy", "--nodes", lom]
    result = run_cmd(cmd, return_dict=True)
    if not result["success"]:
        logger.error(f"[{lom}] Deploy command failed: {result['error']}")
        return False

    return wait_for_status(
        lom, ["Deploy completed", "Up to date", "Success", "Failed"],
        DEPLOY_CHECK_INTERVAL, MAX_DEPLOY_ATTEMPTS, "Deployment"
    )


def is_up_to_date(lom: str) -> bool:
    """Check if node is fully up to date."""
    status = get_node_status(lom)
    if not status:
        return False
    return any(kw in status.lower() for kw in ["up to date", "current", "no update"])


def setup_directories(lom: str) -> Tuple[str, str, str, str]:
    """Create timestamped dirs."""
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{REPORT_BASE_PATH}/{lom}/{ts}"
    reports = os.path.join(base, "reports")
    os.makedirs(reports, exist_ok=True)
    subprocess.run(["sudo", "chmod", "-R", PERMISSION_DIR, base], check=True)
    return base, reports, ts


def generate_http_url(path: str) -> str:
    base_url = os.environ.get("REPORT_BASE_URL", "http://bmi-dev.optum.com")
    return f"{base_url}{path}"


# === MAIN SERVICE ===
def checkfirmware_service(
    lom: str, username: str, password: str, node_type: str,
    node_gen: str, deploy: bool, hostname: str = None
) -> Dict:
    """Main 13-step workflow."""
    start_time = time.time()
    result = {
        "node": lom, "success": False, "status": "unknown",
        "html_report_url": None, "checkfirmware_report": None,
        "execution_time_formatted": "0m 0s"
    }

    base_dir, reports_dir, timestamp = setup_directories(lom)
    baseline_path = BASELINE_PATH_TEMPLATE.format(node_gen=node_gen)

    # === STEP 1: Check getnodes --details ===
    logger.info(f"[{lom}] STEP 1: Checking node status")
    initial_status = get_node_status(lom)

    # === STEP 2: Remove node ===
    if not ensure_node_removed(lom):
        return {**result, "status": "Failed to remove node"}

    # === STEP 3: Re-add node ===
    if not add_node(lom, username, password, node_type):
        return {**result, "status": "Failed to add node"}

    # === STEP 4: Set node attributes ===
    if not set_node_attributes(lom):
        return {**result, "status": "Failed to set node attributes"}

    # === STEP 5: Set session report_dir ===
    if not set_session_report_dir(reports_dir):
        return {**result, "status": "Failed to set report_dir"}

    # === STEP 6: Run inventory ===
    if not run_inventory(lom, baseline_path):
        return {**result, "status": "Inventory failed"}

    # === STEP 7: Generate PRE-deploy HTML report ===
    report_paths = generate_deploy_preview_report(lom, reports_dir)
    run_time = f"{int((time.time() - start_time) // 60)}m {int((time.time() - start_time) % 60)}s"
    update_required = not is_up_to_date(lom)
    html_path = generate_html_report(lom, reports_dir, base_dir, node_gen, baseline_path, run_time, update_required)
    pre_report_url = generate_http_url(html_path) if html_path else None

    if deploy:
        result["checkfirmware_PRE_report"] = pre_report_url
    else:
        result["checkfirmware_report"] = pre_report_url

    # === DEPLOYMENT BLOCK ===
    if deploy:
        # === STEP 8: Ensure power on ===
        ensure_power_on(lom, hostname)

        # === STEP 9: Run deploy ===
        deployed = False
        for attempt in range(2):  # Max 2 attempts
            logger.info(f"[{lom}] DEPLOY ATTEMPT {attempt + 1}")
            if run_deploy(lom):
                if is_up_to_date(lom):
                    deployed = True
                    logger.info(f"[{lom}] Node is now up to date")
                    break
                else:
                    logger.warning(f"[{lom}] Still not up to date, retrying...")
            else:
                logger.error(f"[{lom}] Deploy failed on attempt {attempt + 1}")

        # === STEP 10–13: Post-deploy inventory + report ===
        if deployed:
            post_dir = os.path.join(base_dir, "post_deploy_reports")
            os.makedirs(post_dir, exist_ok=True)
            subprocess.run(["sudo", "chmod", "-R", PERMISSION_DIR, post_dir], check=True)

            run_inventory(lom, baseline_path)
            post_csvs = generate_deploy_preview_report(lom, post_dir)
            post_run_time = f"{int((time.time() - start_time) // 60)}m {int((time.time() - start_time) % 60)}s"
            post_html = generate_html_report(lom, post_dir, base_dir, node_gen, baseline_path, post_run_time, False)
            post_url = generate_http_url(post_html) if post_html else None
            result["checkfirmware_report"] = post_url
        else:
            result["status"] = "Deployment failed after retries"

    # === FINALIZE ===
    exec_sec, exec_fmt = (round(time.time() - start_time, 2),
                          f"{int((time.time() - start_time) // 60)}m {int((time.time() - start_time) % 60)}s")
    result.update({
        "success": bool(result.get("checkfirmware_report")),
        "status": get_node_status(lom) or result["status"],
        "execution_time_formatted": exec_fmt,
        "execution_time_seconds": exec_sec
    })

    logger.info(f"[{lom}] Service completed in {exec_fmt}")
    return result
