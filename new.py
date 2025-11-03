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

from .sum_report_gen import parse_sum_report_to_html
import app.ZTP as ZTP

# === Constants ===
CHECKFIRMWARE_EXEC = "/usr/sbin/smartupdate"
REPORT_BASE_PATH = "/pub/reports/sum"
PERMISSION_DIR = "755"
PERMISSION_FILE = "644"
BASE_URL = os.environ.get("REPORT_BASE_URL", "http://bmi-dev.optum.com")

# === Logging ===
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# === Global for first smartupdate YES prompt ===
_first_smartupdate_called = False


# === Core Utilities ===
def run_cmd(cmd: List[str], timeout: int = 1800, return_dict: bool = False) -> Optional[Dict | str]:
    """Run command with special handling for first smartupdate (YES prompt)."""
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
            return result if return_dict else (output if success else None)
        except subprocess.TimeoutExpired:
            process.kill(); process.communicate()
            return {"success": False, "error": "Timeout", "returncode": -1} if return_dict else None
        except Exception as e:
            return {"success": False, "error": str(e), "returncode": -1} if return_dict else None
    else:
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout, env=os.environ.copy())
            return {"success": True, "output": result.stdout, "error": result.stderr, "returncode": 0} if return_dict else result.stdout
        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Timeout", "returncode": -1} if return_dict else None
        except subprocess.CalledProcessError as e:
            return {"success": False, "output": e.stdout, "error": e.stderr, "returncode": e.returncode} if return_dict else None


def parse_node_status(output: str, lom: str) -> Optional[str]:
    """Parse Node Status: line."""
    if not output:
        return None
    for line in output.splitlines():
        if line.strip().startswith("Node Status:"):
            return line.split(":", 1)[1].strip()
    match = re.search(rf"{re.escape(lom)}.*?Node Status:\s*([^\n]+)", output, re.DOTALL)
    return match.group(1).strip() if match else None


def get_node_status(lom: str) -> Optional[str]:
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "getnodes", lom, "--details"]
    output = run_cmd(cmd)
    return parse_node_status(output, lom) if output else None


def wait_for_status(lom: str, in_progress_keywords: List[str], timeout_min: int, check_interval: int = 30) -> bool:
    """Generic wait with status logging."""
    max_attempts = (timeout_min * 60) // check_interval
    log_interval = max(1, 120 // check_interval)  # Log every 2 min
    prev_status = None

    for attempt in range(max_attempts):
        status = get_node_status(lom)
        elapsed = (attempt + 1) * check_interval
        mins, secs = divmod(elapsed, 60)

        if status != prev_status:
            logger.info(f"[{lom}] Status: '{status}' ({mins}m {secs}s)")
        elif attempt % log_interval == 0:
            logger.info(f"[{lom}] Still: '{status}' ({mins}m {secs}s / {timeout_min}m)")

        if status and not any(kw.lower() in status.lower() for kw in in_progress_keywords):
            logger.info(f"[{lom}] Operation complete: {status}")
            return True

        prev_status = status
        if attempt < max_attempts - 1:
            time.sleep(check_interval)

    logger.error(f"[{lom}] Timed out after {timeout_min} minutes")
    return False


def ensure_node_exists(lom: str, username: str, password: str, node_type: str) -> bool:
    """Check → delete if auth fail → re-add → set attributes."""
    status = get_node_status(lom)

    if status and "incorrect username/password" in status.lower():
        logger.info(f"[{lom}] Auth failure → deleting and re-adding")
        run_cmd(["sudo", CHECKFIRMWARE_EXEC, "delete", "--nodes", lom])

    if not status or "incorrect username/password" in status.lower():
        logger.info(f"[{lom}] Adding node")
        add_cmd = [
            "sudo", CHECKFIRMWARE_EXEC, "add", "--nodes", lom,
            f"user={username}", f"password={shlex.quote(password)}", f"type={node_type}"
        ]
        if not run_cmd(add_cmd):
            logger.error(f"[{lom}] Failed to add node")
            return False

    return verify_and_set_node_attributes(lom)


def verify_and_set_node_attributes(lom: str) -> bool:
    """Ensure all required attributes are set."""
    required = {
        "ignore_warnings": "true",
        "ignore_tpm": "true",
        "failed_dependency": "OMITHOST",
        "skip_prereqs": "true",
        "action": "ifneeded"
    }

    cmd_get = ["sudo", CHECKFIRMWARE_EXEC, "getattributes", "--nodes", lom]
    output = run_cmd(cmd_get)
    if not output:
        return False

    current = {}
    for line in output.splitlines():
        if ":" in line:
            k, v = map(str.strip, line.split(":", 1))
            current[k.lower()] = v.lower()

    to_set = [f"{k}={v}" for k, v in required.items() if current.get(k, "") != v]
    if to_set:
        logger.info(f"[{lom}] Setting attributes: {', '.join(to_set)}")
        cmd_set = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--nodes", lom] + to_set
        if not run_cmd(cmd_set):
            return False

    # Re-verify
    output2 = run_cmd(cmd_get)
    current2 = {}
    for line in output2.splitlines() if output2 else []:
        if ":" in line:
            k, v = map(str.strip, line.split(":", 1))
            current2[k.lower()] = v.lower()

    missing = [k for k, v in required.items() if current2.get(k, "") != v]
    if missing:
        logger.error(f"[{lom}] Attributes still incorrect: {missing}")
        return False

    logger.info(f"[{lom}] All node attributes verified")
    return True


def run_inventory(lom: str, baseline_path: str) -> bool:
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "inventory", "--nodes", lom, "--baselines", baseline_path]
    if not run_cmd(cmd):
        return False
    return wait_for_status(lom, ["inventory started"], timeout_min=30)


def generate_deploy_preview_report(lom: str, reports_dir: str) -> List[str]:
    cmd = ["sudo", CHECKFIRMWARE_EXEC, "generatereports", "--type", "Installables", "--output", "csv", "--nodes", lom]
    output = run_cmd(cmd)
    if not output:
        return []

    paths = []
    for match in re.finditer(r"(/pub/reports/[^ \n]+\.csv)", output):
        src = match.group(1)
        dest = os.path.join(reports_dir, Path(src).name)
        if Path(src).exists():
            if move_and_set_permissions(src, dest, lom):
                paths.append(dest)
    return paths


def move_and_set_permissions(src: str, dest: str, lom: str) -> Optional[str]:
    try:
        if src != dest:
            subprocess.run(["sudo", "mv", src, dest], check=True)
        mode = PERMISSION_FILE if Path(dest).is_file() else PERMISSION_DIR
        subprocess.run(["sudo", "chmod", mode, dest], check=True)
        if Path(dest).is_dir():
            subprocess.run(["sudo", "chmod", "-R", mode, dest], check=True)
        return dest
    except subprocess.CalledProcessError as e:
        logger.error(f"[{lom}] Permission/move failed: {e}")
        return None


def generate_html_report(lom: str, csv_dir: str, base_dir: str, node_gen: str, baseline: str, run_time: str, update_required: bool) -> Optional[str]:
    csv_files = glob.glob(os.path.join(csv_dir, "*.csv"))
    if not csv_files:
        return None

    csv_path = csv_files[0]
    with open(csv_path, 'r') as f:
        csv_content = f.read()

    html = parse_sum_report_to_html(
        csv_content, server_name=lom, node_gen=node_gen,
        baseline_path=baseline, run_time=run_time, update_required=update_required
    )

    html_name = f"{Path(csv_path).stem}.html"
    html_path = os.path.join(base_dir, html_name)
    with open(html_path, 'w') as f:
        f.write(html)

    set_readable_permissions(html_path, lom)
    return html_path


def set_readable_permissions(path: str, lom: str) -> bool:
    try:
        mode = PERMISSION_FILE if Path(path).is_file() else PERMISSION_DIR
        subprocess.run(["sudo", "chmod", mode, path], check=True)
        if Path(path).is_dir():
            subprocess.run(["sudo", "chmod", "-R", mode, path], check=True)
        return True
    except Exception as e:
        logger.error(f"[{lom}] chmod failed on {path}: {e}")
        return False


def ensure_power_on(lom: str, hostname: str = None) -> bool:
    try:
        target = hostname or lom
        server = ZTP.Actions(target)
        if not server.hardware:
            return True  # Skip if unknown

        if "dell" in server.hardware.lower():
            from app.ZTP.dell import DellServer
            svr = DellServer(server.lomip, server.lomuser, server.lompass)
        elif "hp" in server.hardware.lower():
            from app.ZTP.hphpe import HpHpeServer
            svr = HpHpeServer(server.lomip, server.lomuser, server.lompass)
        else:
            return True

        status = svr.get_power_status().lower()
        if status != "on":
            logger.info(f"[{lom}] Powering on server...")
            svr.set_power_on()
            time.sleep(60)
            for _ in range(3):
                if svr.get_power_status().lower() == "on":
                    break
                time.sleep(20)
        else:
            time.sleep(10)  # Stabilize
        return True
    except Exception as e:
        logger.warning(f"[{lom}] Power management failed: {e}")
        return True  # Proceed anyway


def run_deploy_with_retry(lom: str) -> Tuple[bool, str]:
    """Run deploy, monitor, retry once if not up-to-date."""
    for attempt in range(2):
        logger.info(f"[{lom}] Starting deployment (attempt {attempt + 1})")
        cmd = ["sudo", CHECKFIRMWARE_EXEC, "deploy", "--nodes", lom]
        result = run_cmd(cmd, return_dict=True)
        if not result or not result["success"]:
            return False, "Deploy command failed"

        if not wait_for_status(lom, ["deploy started", "deploying", "installing", "reboot"], timeout_min=60):
            return False, "Deploy timeout"

        status = get_node_status(lom) or ""
        if any(kw in status.lower() for kw in ["up to date", "current", "success"]):
            return True, status
        logger.warning(f"[{lom}] Not up-to-date after deploy: {status} → retrying")

    return False, status


# === Main Function ===
def checkfirmware_service(
    lom: str, username: str, password: str, node_type: str,
    node_gen: str, deploy: bool, hostname: str = None
) -> Dict:
    start_time = time.time()
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = f"{REPORT_BASE_PATH}/{lom}/{timestamp}"
    reports_dir = f"{base_dir}/reports"
    post_dir = f"{base_dir}/post_deploy_reports"
    Path(reports_dir).mkdir(parents=True, exist_ok=True)
    Path(post_dir).mkdir(parents=True, exist_ok=True)

    result = {
        "node": lom, "success": False, "status": "unknown", "html_report_url": None,
        "checkfirmware_PRE_report": None, "checkfirmware_report": None,
        "execution_time_formatted": "0m 0s"
    }

    # Set session report dir
    if not run_cmd(["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--session", f"report_dir={reports_dir}"]):
        return {**result, "status": "Failed to set report_dir"}

    baseline_path = f"/pub/spp/{node_gen}_spp_current/packages"

    # === Node Lifecycle ===
    if not ensure_node_exists(lom, username, password, node_type):
        return {**result, "status": "Node add/attr failed"}

    # === Inventory ===
    if not run_inventory(lom, baseline_path):
        return {**result, "status": "Inventory failed"}

    # === Pre-Deploy Report ===
    pre_csvs = generate_deploy_preview_report(lom, reports_dir)
    update_needed = get_node_status(lom)
    update_needed = bool(update_needed and "update" in update_needed.lower())

    pre_html = generate_html_report(
        lom, reports_dir, base_dir, node_gen, baseline_path,
        run_time="Pre-deploy", update_required=update_needed
    )
    pre_url = f"{BASE_URL}{pre_html}" if pre_html else None
    if deploy:
        result["checkfirmware_PRE_report"] = pre_url
    else:
        result["checkfirmware_report"] = pre_url

    # === Deploy Path ===
    if deploy:
        ensure_power_on(lom, hostname)
        verify_and_set_node_attributes(lom)

        success, final_status = run_deploy_with_retry(lom)
        if not success:
            result["status"] = f"Deploy failed: {final_status}"
        else:
            # Post-deploy inventory
            run_inventory(lom, baseline_path)
            post_csvs = generate_deploy_preview_report(lom, post_dir)
            post_html = generate_html_report(
                lom, post_dir, base_dir, node_gen, baseline_path,
                run_time="Post-deploy", update_required=False
            )
            if post_html:
                new_name = os.path.join(base_dir, f"post_deploy_{Path(post_html).name}")
                subprocess.run(["sudo", "mv", post_html, new_name], check=True)
                set_readable_permissions(new_name, lom)
                result["checkfirmware_report"] = f"{BASE_URL}{new_name}"

    # === Finalize ===
    subprocess.run(["sudo", "chmod", "-R", "755", base_dir], check=True)
    exec_sec, exec_str = divmod(int(time.time() - start_time), 60)
    result.update({
        "success": True, "status": get_node_status(lom) or "unknown",
        "execution_time_formatted": f"{exec_sec // 60}m {exec_sec % 60}s"
    })

    logger.info(f"[{lom}] Completed in {result['execution_time_formatted']}")
    return result
