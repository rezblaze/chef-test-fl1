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
DEFAULT_TIMEOUT = 1800
REPORT_BASE_PATH = "/pub/reports/sum"

NODE_ATTRIBUTES_SET = {
    "ignore_warnings": "true",
    "ignore_tpm": "true",
    "action": "ifneeded",
    "skip_prereqs": "true",
    "rewrite": "true"
}

NODE_ATTRIBUTES_VERIFY = {
    "ignore_warnings": "true",
    "ignore_tpm": "true",
    "action": "If Needed",
    "skip_prereqs": "true",
    "rewrite": "true"
}

CLEAN_STATUSES = {"clean", "up to date", "no updates available"}

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)


# === Core Utilities ===
def run_cmd(cmd: List[str], timeout: int = DEFAULT_TIMEOUT, return_dict: bool = False) -> Optional[dict | str]:
    """Run command with special handling for first smartupdate call."""
    global _first_smartupdate_called
    _first_smartupdate_called = globals().get("_first_smartupdate_called", False)

    is_smartupdate = len(cmd) >= 2 and cmd[1] == CHECKFIRMWARE_EXEC

    if is_smartupdate and not _first_smartupdate_called:
        try:
            process = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                text=True, env=os.environ.copy(), stdin=subprocess.PIPE
            )
            output, error = process.communicate(input="YES\n", timeout=timeout)
            globals()["_first_smartupdate_called"] = True
            return _format_result(process, output, error, return_dict)
        except Exception as e:
            logger.error(f"First smartupdate failed: {e}")
            return _error_result(str(e), return_dict)
    else:
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=timeout, env=os.environ.copy())
            return _format_result(result, result.stdout, result.stderr, return_dict)
        except subprocess.TimeoutExpired:
            logger.warning(f"Command timed out: {' '.join(cmd)}")
            return _error_result("timeout", return_dict)
        except subprocess.CalledProcessError as e:
            return _format_result(e, e.stdout or "", e.stderr or "", return_dict, success=False)
        except Exception as e:
            return _error_result(str(e), return_dict)


def _format_result(proc, out, err, return_dict, success=True):
    if return_dict:
        return {"success": success and proc.returncode == 0, "output": out, "error": err, "returncode": proc.returncode}
    return out if success and proc.returncode == 0 else None


def _error_result(msg: str, return_dict: bool):
    if return_dict:
        return {"success": False, "output": "", "error": msg, "returncode": -1}
    return None


def parse_node_status(output: str, lom: str) -> Optional[str]:
    if not output:
        return None
    for line in output.splitlines():
        if line.strip().startswith("Node Status:"):
            status = line.split(":", 1)[1].strip()
            logger.debug(f"[{lom}] Parsed status: {status}")
            return status
    match = re.search(rf"{re.escape(lom)}\b.*Node Status:\s*([^\n]+)", output, re.DOTALL)
    if match:
        status = match.group(1).strip()
        logger.debug(f"[{lom}] Regex fallback status: {status}")
        return status
    return None


def get_node_status(lom: str) -> Optional[str]:
    output = run_cmd(["sudo", CHECKFIRMWARE_EXEC, "getnodes", lom, "--details"])
    return parse_node_status(output, lom) if output else None


def wait_for_completion(lom: str, process: str, keywords: List[str], max_min: int = 30) -> bool:
    interval, attempts = 30, (max_min * 60) // 30
    prev = None
    for i in range(attempts):
        status = get_node_status(lom)
        elapsed = f"{(i + 1) * 30 // 60}m {(i + 1) * 30 % 60}s"
        if status:
            if status != prev:
                logger.info(f"[{lom}] Status: '{status}' ({elapsed})")
            elif (i + 1) % 4 == 0:
                logger.info(f"[{lom}] Still: '{status}' ({elapsed})")
            if "deployment" in process.lower():
                output = run_cmd(["sudo", CHECKFIRMWARE_EXEC, "getnodes", lom, "--details"]) or ""
                for line in output.strip().splitlines():
                    logger.info(f"[{lom}] DEPLOY: {line}")
            if not any(k in status.lower() for k in keywords):
                logger.info(f"[{lom}] {process} complete: {status}")
                return True
            prev = status
        else:
            logger.warning(f"[{lom}] No status (attempt {i + 1})")
        if i < attempts - 1:
            time.sleep(interval)
    logger.error(f"[{lom}] {process} timed out after {max_min} min")
    return False


def ensure_power_on(lom: str, hostname: str = None) -> bool:
    target = hostname or lom
    try:
        action = ZTP.Actions(target)
        if "hp" not in getattr(action, "hardware", "").lower():
            logger.warning(f"[{lom}] Not HPE hardware")
            return False
        from app.ZTP.hphpe import HpHpeServer
        server = HpHpeServer(action.lomip, action.lomuser, action.lompass)
        status = server.get_power_status()
        logger.info(f"[{lom}] Power: {status}")
        if status.lower() != "on":
            logger.info(f"[{lom}] Powering on...")
            server.set_power_on()
            time.sleep(60)
            logger.info(f"[{lom}] Post-power status: {server.get_power_status()}")
        else:
            time.sleep(10)
        return True
    except Exception as e:
        logger.warning(f"[{lom}] Power check failed: {e}")
        return False


# === Report & File Handling ===
def prepare_dirs(lom: str) -> Tuple[str, str, str, str]:
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = f"{REPORT_BASE_PATH}/{lom}/{ts}"
    reports = f"{base}/reports"
    temp = f"{base}/temp"
    os.makedirs(reports, exist_ok=True)
    os.makedirs(temp, exist_ok=True)
    subprocess.run(["sudo", "chmod", "-R", "755", base], check=True)
    return base, reports, temp, ts


def move_and_permit(src: str, dst: str, lom: str) -> Optional[str]:
    try:
        if src != dst:
            subprocess.run(["sudo", "mv", src, dst], check=True)
        subprocess.run(["sudo", "chmod", "644" if Path(dst).is_file() else "-R", "755", dst], check=True)
        return dst
    except Exception as e:
        logger.error(f"[{lom}] Move/permission failed: {e}")
        return None


def generate_html(lom: str, reports_dir: str, base_dir: str, **kwargs) -> Optional[str]:
    csvs = glob.glob(f"{reports_dir}/*.csv")
    if not csvs:
        return None
    csv = csvs[0]
    with open(csv, 'r') as f:
        content = f.read()
    html = parse_sum_report_to_html(content, server_name=lom, **kwargs)
    name = f"{Path(csv).stem}.html"
    path = f"{base_dir}/{name}"
    with open(path, 'w') as f:
        f.write(html)
    subprocess.run(["sudo", "chmod", "644", path], check=True)
    logger.info(f"[{lom}] HTML report: {path}")
    return path


def http_url(path: str) -> Optional[str]:
    if not path or not path.startswith("/pub/reports/sum"):
        return None
    base = os.environ.get("REPORT_BASE_URL", "http://bmi-dev.optum.com")
    return f"{base}{path}"


# === Node Attribute Management ===
def verify_and_log_attributes(lom: str) -> bool:
    output = run_cmd(["sudo", CHECKFIRMWARE_EXEC, "getattributes", "--nodes", lom])
    if not output:
        logger.error(f"[{lom}] Failed to get attributes")
        return False

    logger.info(f"[{lom}] === CURRENT NODE ATTRIBUTES ===")
    for line in output.strip().splitlines():
        logger.info(f"[{lom}] ATTR: {line}")
    logger.info(f"[{lom}] === END ATTRIBUTES ===")

    attrs = {}
    for line in output.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            attrs[k.strip().lower()] = v.strip()

    missing = []
    for k, exp in NODE_ATTRIBUTES_VERIFY.items():
        cur = attrs.get(k.lower(), "").lower()
        if cur != exp.lower():
            missing.append(f"{k}={NODE_ATTRIBUTES_SET[k]}")

    if missing:
        logger.warning(f"[{lom}] Fixing attributes: {', '.join(missing)}")
        cmd = ["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--nodes", lom] + missing
        return bool(run_cmd(cmd))
    logger.info(f"[{lom}] All attributes correctly set")
    return True


# === Main Workflow ===
def checkfirmware_service(
    lom: str, username: str, password: str, node_type: str,
    node_gen: str, deploy: bool, hostname: str = None
) -> Dict:

    start = time.time()
    result = {
        "node": lom, "success": False, "status": None, "status_detail": None,
        "html_report_url": None, "checkfirmware_report": None, "checkfirmware_PRE_report": None,
        "execution_time_seconds": 0, "execution_time_formatted": "0m 0s"
    }

    base_dir, reports_dir, temp_dir, ts = prepare_dirs(lom)
    baseline = f"/pub/spp/{node_gen}_spp_current/packages"

    # === 1. Check initial status ===
    initial_status = get_node_status(lom)
    logger.info(f"[{lom}] Initial status: {initial_status}")

    if initial_status and not any(clean in initial_status.lower() for clean in CLEAN_STATUSES):
        logger.info(f"[{lom}] Node not clean. Status: {initial_status}. Stopping.")
        result.update({
            "status": initial_status, "status_detail": initial_status,
            "execution_time_seconds": round(time.time() - start, 2)
        })
        return result

    # === 2. Clean add node ===
    run_cmd(["sudo", CHECKFIRMWARE_EXEC, "delete", "--nodes", lom])
    add_cmd = ["sudo", CHECKFIRMWARE_EXEC, "add", "--nodes", lom,
               f"user={username}", f"password={shlex.quote(password)}", f"type={node_type}"]
    if not run_cmd(add_cmd):
        return _fail(result, "Failed to add node", start)

    # === 3. Set & verify attributes (CRITICAL) ===
    attrs = [f"{k}={v}" for k, v in NODE_ATTRIBUTES_SET.items()]
    if not run_cmd(["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--nodes", lom] + attrs):
        return _fail(result, "Failed to set attributes", start)
    if not verify_and_log_attributes(lom):
        return _fail(result, "Attribute verification failed", start)

    # === 4. Session report dir ===
    if not run_cmd(["sudo", CHECKFIRMWARE_EXEC, "setattributes", "--session", f"report_dir={reports_dir}"]):
        return _fail(result, "Failed to set session report dir", start)

    # === 5. Inventory ===
    if not run_cmd(["sudo", CHECKFIRMWARE_EXEC, "inventory", "--nodes", lom, "--baselines", baseline]):
        return _fail(result, "Inventory failed", start)
    if not wait_for_completion(lom, "Inventory", ["inventory started"]):
        return _fail(result, "Inventory timeout", start)

    # === 6. Generate preview report ===
    report_out = run_cmd(["sudo", CHECKFIRMWARE_EXEC, "generatereports", "--type", "Installables", "--output", "csv", "--nodes", lom])
    report_paths = []
    if report_out:
        for match in re.finditer(r"(/pub/reports/[^ \n]+\.csv)", report_out):
            src = match.group(1)
            dst = f"{reports_dir}/{Path(src).name}"
            if moved := move_and_permit(src, dst, lom):
                report_paths.append(moved)

    # === 7. Generate HTML (pre-deploy) ===
    cur_status = get_node_status(lom)
    update_needed = cur_status and any(k in cur_status.lower() for k in ["update required", "update"])
    html_path = generate_html(
        lom, reports_dir, base_dir, node_gen=node_gen, baseline_path=baseline,
        run_time="...", update_required=update_needed, current_node_status=cur_status
    )
    html_url = http_url(html_path) if html_path else None
    if deploy:
        result["checkfirmware_PRE_report"] = html_url
    else:
        result["checkfirmware_report"] = html_url

    # === 8. Deploy (if requested) ===
    if deploy and update_needed:
        ensure_power_on(lom, hostname)
        logger.info(f"[{lom}] Starting deployment...")
        deploy_cmd = ["sudo", CHECKFIRMWARE_EXEC, "deploy", "--nodes", lom]
        if run_cmd(deploy_cmd, return_dict=True).get("success"):
            wait_for_completion(lom, "Deployment", ["deploy", "installing", "reboot"], 60)
            if not any(get_node_status(lom) or "".lower() in CLEAN_STATUSES):
                logger.info(f"[{lom}] Retry deploy...")
                run_cmd(deploy_cmd)
                wait_for_completion(lom, "Retry Deployment", ["deploy", "installing", "reboot"], 60)

        # Post-deploy report
        run_cmd(["sudo", CHECKFIRMWARE_EXEC, "inventory", "--nodes", lom, "--baselines", baseline])
        wait_for_completion(lom, "Post-inventory", ["inventory started"])
        post_out = run_cmd(["sudo", CHECKFIRMWARE_EXEC, "generatereports", "--type", "Installables", "--output", "csv", "--nodes", lom])
        post_dir = f"{base_dir}/post_deploy_reports"
        os.makedirs(post_dir, exist_ok=True)
        post_paths = []
        for m in re.finditer(r"(/pub/reports/[^ \n]+\.csv)", post_out or ""):
            src, name = m.group(1), Path(m.group(1)).name
            dst = f"{post_dir}/post_{name}"
            if moved := move_and_permit(src, dst, lom):
                post_paths.append(moved)
        if post_paths:
            final_status = get_node_status(lom)
            post_html = generate_html(
                lom, post_dir, base_dir, node_gen=node_gen, baseline_path=baseline,
                run_time="...", update_required=False, current_node_status=final_status
            )
            if post_html:
                final_post = f"{base_dir}/post_deploy_report.html"
                subprocess.run(["sudo", "mv", post_html, final_post], check=True)
                subprocess.run(["sudo", "chmod", "644", final_post], check=True)
                result["checkfirmware_report"] = http_url(final_post)

    # === Finalize ===
    try:
        subprocess.run(["sudo", "rm", "-rf", temp_dir], check=True)
    except:
        pass

    final_status = get_node_status(lom)
    sec, fmt = _time_diff(start)
    result.update({
        "status": initial_status or final_status,
        "status_detail": final_status,
        "success": bool(html_url),
        "execution_time_seconds": sec,
        "execution_time_formatted": fmt
    })
    logger.info(f"[{lom}] Completed in {fmt}")
    return result


def _fail(result: dict, msg: str, start: float):
    sec, fmt = _time_diff(start)
    result.update({"status": msg, "execution_time_seconds": sec, "execution_time_formatted": fmt})
    return result


def _time_diff(start: float) -> tuple:
    diff = time.time() - start
    return round(diff, 2), f"{int(diff // 60)}m {int(diff % 60)}s"
