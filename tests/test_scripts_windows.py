"""Windows PowerShell 5.1 interaction and failure handling, without live releases."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MANAGER = ROOT / "scripts/manage/manage.ps1"
pytestmark = pytest.mark.skipif(os.name != "nt", reason="Requires Windows PowerShell 5.1")


def powershell(script, *args, stdin=None, timeout=45, env=None):
    return subprocess.run(
        ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(script), *args],
        input=stdin, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONDONTWRITEBYTECODE": "1", **(env or {})},
    )


def snapshot(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


@pytest.fixture
def query_manager(tmp_path):
    config, runtime, output = (tmp_path / name for name in ("config", "runtime", "dist"))
    (config / "local").mkdir(parents=True)
    (config / "rule-sets").mkdir()
    (config / "policy.yaml").write_text(json.dumps({"groups": {}, "config": {
        "dns": {"rules": []}, "route": {"rules": []}}}))
    (config / "local/a.json").write_text(json.dumps({"outbounds": []}))
    (config / "local/subscriptions.yaml").write_text(json.dumps({"subscriptions": [
        {"name": "Test source", "path": "a.json"}]}))

    def invoke(action, *extra, stdin=None):
        return powershell(MANAGER, "-Action", action, "-ConfigRoot", str(config),
                          "-RuntimeRoot", str(runtime), "-OutputRoot", str(output), *extra, stdin=stdin,
                          env={"SING_BOX_CORE": str(tmp_path / "missing-core.exe")})

    return invoke, tmp_path


@pytest.mark.parametrize("action,extra", [
    ("add", []), ("add", ["-Name", "Test"]), ("remove", []), ("disable", []),
    ("enable", []), ("rollback", []), ("explain", []), ("menu", []), ("maintain", []),
    ("all", ["-Json"]), ("unknown", []), ("status", ["-Platform", "invalid"]),
])
def test_noninteractive_missing_or_invalid_parameters_exit_2(query_manager, action, extra):
    invoke, root = query_manager
    before = snapshot(root)
    result = invoke(action, "-NonInteractive", *extra)
    assert result.returncode == 2, result.stdout + result.stderr
    assert "已提交，但" not in result.stdout
    assert snapshot(root) == before


@pytest.mark.parametrize("action", ["status", "sources", "history", "lint", "doctor", "help", "explain"])
def test_readonly_json_is_one_object_without_writes(query_manager, action):
    invoke, root = query_manager
    before = snapshot(root)
    extra = ["-Domain", "example.com"] if action == "explain" else []
    result = invoke(action, "-Json", "-NonInteractive", *extra)
    assert result.returncode == 0, result.stdout + result.stderr
    assert isinstance(json.loads(result.stdout), dict)
    assert snapshot(root) == before


def test_readonly_text_queries_have_chinese_labels(query_manager):
    invoke, root = query_manager
    before = snapshot(root)
    for action, expected in (("status", "活动版本"), ("sources", "节点"), ("lint", "规则结构检查"),
                             ("explain", "客户端实际选择与远端出口未知")):
        result = invoke(action, "-NonInteractive", *(["-Domain", "example.com"] if action == "explain" else []))
        assert result.returncode == 0, result.stdout + result.stderr
        assert expected in result.stdout
    assert snapshot(root) == before


def test_explain_text_includes_final_fallback_targets(query_manager):
    invoke, root = query_manager
    policy = root / "config/policy.yaml"
    data = json.loads(policy.read_text())
    data["config"]["route"]["final"] = "direct"
    data["config"]["dns"]["final"] = "dns-final"
    policy.write_text(json.dumps(data))
    before = snapshot(root)
    result = invoke("explain", "-Domain", "example.com", "-NonInteractive")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "final / direct" in result.stdout
    assert "final / dns-final" in result.stdout
    assert snapshot(root) == before


def test_json_missing_domain_does_not_prompt(query_manager):
    invoke, root = query_manager
    before = snapshot(root)
    result = invoke("explain", "-Json")
    assert result.returncode == 2, result.stdout + result.stderr
    assert json.loads(result.stdout)["exit_code"] == 2
    assert snapshot(root) == before


@pytest.mark.parametrize("action", ["publisher", "show-info", "rotate-credentials"])
def test_custom_roots_cannot_use_production_publisher_credentials(query_manager, action):
    invoke, root = query_manager
    before = snapshot(root)
    result = invoke(action, "-NonInteractive")
    assert result.returncode == 2, result.stdout + result.stderr
    assert "自定义根目录下禁止" in result.stdout
    assert snapshot(root) == before


def test_cli_action_and_platform_are_case_insensitive(query_manager):
    invoke, _ = query_manager
    result = invoke("EXPLAIN", "-Domain", "example.com", "-Platform", "Android", "-Json")
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout)["platform"] == "android"


@pytest.mark.parametrize("stdin", [
    "q\n", "1\n1\n\nq\n", "1\n2\nn\nq\n", "2\n1\n1\n\nq\n",
    "2\na\n\nq\n", "3\n1\n\nq\n", "4\n1\n\nq\n", "4\n3\n\nq\n",
    "5\nnot-a-release\n\nq\n", "6\n2\n\nq\n", "6\n3\n\nq\n",
])
def test_menu_cancel_never_changes_state(query_manager, stdin):
    invoke, root = query_manager
    before = snapshot(root)
    result = invoke("menu", stdin=stdin)
    assert result.returncode == 0, result.stdout + result.stderr
    assert "历史版本与回退" in result.stdout
    assert "[错误]" not in result.stdout
    assert snapshot(root) == before


@pytest.mark.parametrize("exit_code", [2, 10])
def test_native_exit_codes_are_preserved_and_classified(tmp_path, exit_code):
    # Extract only helper definitions, so no manager action or production input runs.
    script = tmp_path / "native.ps1"
    script.write_text("""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$errors=$null; $tokens=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
foreach($name in @('ConvertTo-NativeArgument','Invoke-Python')) {
  $node=$tree.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
  . ([scriptblock]::Create($node.Extent.Text))
}
$script:python=$args[1]
$ProjectRoot=$args[2]
function Get-PythonCommand { return @($script:python) }
try { Invoke-Python -Arguments @('-c', ('import sys; sys.exit(' + $args[3] + ')')) }
catch { Write-Output $_.Exception.Message; exit ([int]$_.Exception.Data['ExitCode']) }
""", encoding="utf-8-sig")
    result = powershell(script, str(MANAGER), sys.executable, str(tmp_path), str(exit_code))
    assert result.returncode == exit_code, result.stdout + result.stderr
    assert ("活动版本已提交" in result.stdout) == (exit_code == 10)


def test_native_stdout_and_stderr_are_forwarded_before_process_exit(tmp_path):
    script = tmp_path / "stream.ps1"
    script.write_text("""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
$errors=$null; $tokens=$null
$tree=[Management.Automation.Language.Parser]::ParseFile($args[0],[ref]$tokens,[ref]$errors)
foreach($name in @('ConvertTo-NativeArgument','Invoke-Python')) {
  $node=$tree.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
  . ([scriptblock]::Create($node.Extent.Text))
}
$script:python=$args[1]
$ProjectRoot=$args[2]
function Get-PythonCommand { return @($script:python) }
Invoke-Python -Arguments @('-u', $args[3], $args[4])
""", encoding="utf-8-sig")
    child = tmp_path / "child.py"
    child.write_text("import pathlib, sys, time\nprint('stdout-first', flush=True)\n"
                     "print('stderr-first', file=sys.stderr, flush=True)\n"
                     "time.sleep(2)\npathlib.Path(sys.argv[1]).write_text('done')\n")
    finished = tmp_path / "finished.txt"
    command = ["powershell.exe", "-NoLogo", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
               str(script), str(MANAGER), sys.executable, str(tmp_path), str(child), str(finished)]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="replace") as process:
        try:
            assert process.stdout.readline().strip() == "stdout-first"
            assert process.stderr.readline().strip() == "stderr-first"
            assert not finished.exists(), "Progress was buffered until the child finished"
            stdout, stderr = process.communicate(timeout=20)
            assert process.returncode == 0, stdout + stderr
            assert finished.exists()
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=10)


def test_failed_native_probes_are_recorded_and_sampling_continues(tmp_path):
    report = tmp_path / "connectivity"
    # Python rejects curl flags immediately on stderr; this exercises real failed
    # child processes without making any network requests.
    result = powershell(ROOT / "scripts/quality/diagnose-connectivity.ps1",
                        "-Samples", "2", "-IntervalSeconds", "1", "-ReportRoot", str(report),
                        "-CurlExecutable", sys.executable)
    assert result.returncode == 0, result.stdout + result.stderr
    rows = [json.loads(line) for line in (report / "samples.jsonl").read_text(encoding="utf-8-sig").splitlines()]
    assert len(rows) == 2
    assert all(len(row["probes"]) == 4 for row in rows)
    assert all(probe["exit_code"] != 0 and probe["error"] for row in rows for probe in row["probes"])
    assert {probe["path"] for row in rows for probe in row["probes"]} == {"system", "mixed"}
    assert all(probe["tun_verified"] is False for row in rows for probe in row["probes"])
    assert all("--disable" in probe["error"] for row in rows for probe in row["probes"])


def test_setup_offline_noninteractive_fails_without_environment_and_does_not_write(tmp_path):
    scripts = tmp_path / "scripts/bootstrap"
    scripts.mkdir(parents=True)
    for name in ("setup.ps1", "setup.bat"):
        shutil.copyfile(ROOT / "scripts/bootstrap" / name, scripts / name)
    before = snapshot(tmp_path)
    result = subprocess.run(["cmd.exe", "/d", "/c", str(scripts / "setup.bat"), "-Offline", "-NonInteractive"],
                            capture_output=True, encoding="utf-8", errors="replace", timeout=20)
    assert result.returncode == 1, result.stdout + result.stderr
    assert "离线安装需要已有 .venv" in result.stdout
    assert "NamedParameterNotFound" not in result.stderr
    assert snapshot(tmp_path) == before


def test_setup_help_does_not_initialize_environment(tmp_path):
    scripts = tmp_path / "scripts/bootstrap"
    scripts.mkdir(parents=True)
    shutil.copyfile(ROOT / "scripts/bootstrap/setup.ps1", scripts / "setup.ps1")
    before = snapshot(tmp_path)
    result = powershell(scripts / "setup.ps1", "-Help", "-NonInteractive")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "不会自动下载核心" in result.stdout
    assert snapshot(tmp_path) == before


def test_chinese_powershell_scripts_have_utf8_bom():
    for relative in ("scripts/manage/manage.ps1", "scripts/bootstrap/setup.ps1",
                     "scripts/quality/diagnose-connectivity.ps1"):
        assert (ROOT / relative).read_bytes().startswith(b"\xef\xbb\xbf")
