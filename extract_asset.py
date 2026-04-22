#!/usr/bin/env python3
"""
EC2 인스턴스 내부 자산 정보 추출 스크립트.

--payload 로 payload.json 을 전달하면 해당 파일의 cpe_criteria 에서
탐지 대상 소프트웨어(vendor:product)를 동적으로 결정한다.
실행 결과를 asset_info.json 으로 저장한다.
"""

from __future__ import annotations

import argparse
import json
import re
import socket
import subprocess
import urllib.error
import urllib.request
from pathlib import Path


IMDS_BASE = "http://169.254.169.254/latest/meta-data"
IMDS_TIMEOUT = 2  # seconds


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="EC2 자산 정보를 추출하여 asset_info.json 으로 저장합니다."
    )
    parser.add_argument(
        "--payload",
        default=None,
        help="payload.json 경로. 지정하면 해당 파일의 cpe_criteria 기준으로 탐지 대상을 한정합니다.",
    )
    parser.add_argument(
        "--env",
        dest="environment",
        default="production",
        choices=["production", "staging", "development"],
        help="배포 환경 (default: production)",
    )
    parser.add_argument(
        "--exposure",
        dest="network_exposure",
        default="public",
        choices=["public", "private", "internal"],
        help="네트워크 노출 여부 (default: public)",
    )
    parser.add_argument(
        "--criticality",
        dest="business_criticality",
        default="high",
        choices=["critical", "high", "medium", "low"],
        help="비즈니스 중요도 (default: high)",
    )
    parser.add_argument(
        "--output",
        default="asset_info1.json",
        help="출력 파일 경로 (default: asset_info1.json)",
    )
    return parser.parse_args()


# ---------------------------------------------------------------------------
# payload.json 파싱 → 탐지 대상 추출
# ---------------------------------------------------------------------------

def _parse_cpe_key(criteria: str) -> str | None:
    """
    "cpe:2.3:a:f5:nginx:*:..." → "f5:nginx" 반환.
    파싱 실패 시 None 반환.
    """
    parts = criteria.split(":")
    if len(parts) >= 5 and parts[3] and parts[4]:
        return f"{parts[3].lower()}:{parts[4].lower()}"
    return None


def load_target_keys(payload_path: Path) -> set[str]:
    """
    payload.json 의 모든 records 를 순회하며
    cpe_criteria 에서 "vendor:product" 키 집합을 추출한다.

    예: {"f5:nginx", "apache:log4j"}
    """
    data: dict = json.loads(payload_path.read_text())
    keys: set[str] = set()
    for record in data.get("records", []):
        for criteria in record.get("cpe_criteria", []):
            key = _parse_cpe_key(criteria)
            if key:
                keys.add(key)
    return keys


# ---------------------------------------------------------------------------
# IMDS (Instance Metadata Service)
# ---------------------------------------------------------------------------

def _imds_get(path: str) -> str:
    """IMDS 엔드포인트에서 단일 값을 가져온다. 실패 시 빈 문자열 반환."""
    url = f"{IMDS_BASE}/{path}"
    try:
        with urllib.request.urlopen(url, timeout=IMDS_TIMEOUT) as resp:
            return resp.read().decode().strip()
    except (urllib.error.URLError, OSError):
        return ""


def _imds_get_v2(path: str) -> str:
    """IMDSv2 토큰 방식으로 IMDS 값을 가져온다."""
    token_url = "http://169.254.169.254/latest/api/token"
    try:
        token_req = urllib.request.Request(
            token_url,
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
            method="PUT",
        )
        with urllib.request.urlopen(token_req, timeout=IMDS_TIMEOUT) as resp:
            token = resp.read().decode().strip()

        data_req = urllib.request.Request(
            f"{IMDS_BASE}/{path}",
            headers={"X-aws-ec2-metadata-token": token},
        )
        with urllib.request.urlopen(data_req, timeout=IMDS_TIMEOUT) as resp:
            return resp.read().decode().strip()
    except (urllib.error.URLError, OSError):
        return ""


def get_instance_id() -> str:
    """인스턴스 ID를 반환한다. IMDS 접근 불가 시 hostname 으로 대체."""
    instance_id = _imds_get("instance-id")
    if instance_id:
        return instance_id
    instance_id = _imds_get_v2("instance-id")
    if instance_id:
        return instance_id
    return socket.gethostname()


# ---------------------------------------------------------------------------
# OS 정보
# ---------------------------------------------------------------------------

def get_os_info() -> dict:
    """
    /etc/os-release 를 파싱하여 vendor / version 을 반환한다.
    파일이 없으면 'unknown' 으로 채운다.
    """
    os_release = Path("/etc/os-release")
    vendor, version = "unknown", "unknown"

    if not os_release.exists():
        return {"vendor": vendor, "version": version}

    kv: dict[str, str] = {}
    for line in os_release.read_text().splitlines():
        line = line.strip()
        if "=" not in line or line.startswith("#"):
            continue
        key, _, val = line.partition("=")
        kv[key.strip()] = val.strip().strip('"')

    vendor = kv.get("ID", "unknown").lower()

    if "VERSION_ID" in kv:
        version = kv["VERSION_ID"]
    elif "VERSION" in kv:
        m = re.search(r"[\d.]+", kv["VERSION"])
        version = m.group(0) if m else kv["VERSION"]

    return {"vendor": vendor, "version": version}


# ---------------------------------------------------------------------------
# 공통 유틸
# ---------------------------------------------------------------------------

def _run(cmd: list[str], timeout: int = 5) -> tuple[str, str]:
    """명령어 실행 후 (stdout, stderr) 반환. 실행 불가 시 빈 문자열."""
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
        )
        return result.stdout.decode(errors="replace").strip(), result.stderr.decode(errors="replace").strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return "", ""


def _safe_exists(path: Path) -> bool:
    """PermissionError 를 포함한 모든 OS 오류를 무시하고 존재 여부를 반환한다."""
    try:
        return path.exists()
    except OSError:
        return False


# ---------------------------------------------------------------------------
# 소프트웨어 탐지 함수들
# 각 함수는 탐지 성공 시 dict, 실패 시 None 을 반환한다.
# ---------------------------------------------------------------------------

def detect_nginx() -> dict | None:
    """nginx -v 로 버전을 감지한다. (버전 정보는 stderr 로 출력됨)"""
    stdout, stderr = _run(["nginx", "-v"])
    combined = stderr or stdout

    m = re.search(r"nginx/(\d+\.\d+\.\d+)", combined, re.IGNORECASE)
    if not m:
        return None

    version = m.group(1)
    return {
        "vendor": "f5",
        "product": "nginx",
        "version": version,
        "cpe": f"cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*",
    }


def detect_log4j() -> dict | None:
    """
    Apache Log4j 버전을 아래 순서로 탐지한다.
    1. dpkg / rpm 패키지 매니저
    2. 실행 중인 Java 프로세스 classpath 분석
    3. Fat JAR / Shaded JAR 내부 log4j 클래스 탐색
    4. Maven / Gradle 로컬 캐시 탐색
    5. 독립 JAR 파일 탐색 (fallback)
    """
    # 1. 패키지 매니저
    stdout, _ = _run(["dpkg", "-l"])
    if stdout:
        for line in stdout.splitlines():
            m = re.search(r"log4j[\d.-]*\s+([\d.]+)", line, re.IGNORECASE)
            if m:
                return _log4j_entry(m.group(1))

    stdout, _ = _run(["rpm", "-qa", "--queryformat", "%{NAME} %{VERSION}\n"])
    if stdout:
        for line in stdout.splitlines():
            m = re.match(r"log4j\S*\s+([\d.]+)", line, re.IGNORECASE)
            if m:
                return _log4j_entry(m.group(1))

    # 2. 실행 중인 Java 프로세스 classpath 분석
    # ps 로 java 프로세스를 찾고 -cp / -classpath 또는 /proc/{pid}/cmdline 에서 JAR 경로 추출
    result = _detect_log4j_from_running_process()
    if result:
        return result

    # 3. Fat JAR / Shaded JAR 내부에 log4j 클래스가 내장된 경우 탐색
    # unzip -l 로 내부 경로에 org/apache/logging/log4j 가 있는 JAR 검색
    result = _detect_log4j_in_fat_jar()
    if result:
        return result

    # 4. Maven / Gradle 로컬 캐시
    for cache_root in ["/root/.m2", "/home", "/root/.gradle"]:
        if not _safe_exists(Path(cache_root)):
            continue
        stdout, _ = _run(
            ["find", cache_root, "-maxdepth", "10", "-name", "*log4j*.jar", "-type", "f"],
            timeout=20,
        )
        for jar_path in stdout.splitlines():
            jar_path = jar_path.strip()
            if not jar_path:
                continue
            version = _extract_version_from_jar_name(jar_path)
            if version:
                return _log4j_entry(version, source=jar_path)

    # 5. 독립 JAR fallback (jar 이름에 log4j 없는 경우도 포함)
    for root in ["/usr", "/opt", "/var", "/app", "/srv", "/tmp", "/data"]:
        if not _safe_exists(Path(root)):
            continue
        stdout, _ = _run(
            ["find", root, "-maxdepth", "10", "-name", "*log4j*.jar", "-type", "f"],
            timeout=20,
        )
        for jar_path in stdout.splitlines():
            jar_path = jar_path.strip()
            if not jar_path:
                continue
            version = _extract_version_from_jar_name(jar_path)
            if version:
                return _log4j_entry(version, source=jar_path)
            version = _extract_version_from_jar_manifest(jar_path)
            if version:
                return _log4j_entry(version, source=jar_path)

    return None


def _detect_log4j_from_running_process() -> dict | None:
    """
    실행 중인 Java 프로세스의 /proc/{pid}/cmdline 을 파싱해 탐지한다.

    케이스 A — classpath(-cp/-classpath) 토큰에 log4j JAR 이름이 직접 포함된 경우
    케이스 B — `-jar app.jar` 처럼 이름에 log4j 가 없는 Fat JAR 로 실행된 경우:
               JAR 내부의 BOOT-INF/lib/ 또는 pom.properties 를 조회해 버전 판별
    """
    proc = Path("/proc")
    if not proc.exists():
        return None

    for pid_dir in proc.iterdir():
        if not pid_dir.name.isdigit():
            continue
        cmdline_file = pid_dir / "cmdline"
        try:
            # null byte(\x00) 로 구분된 인자 배열
            args = cmdline_file.read_bytes().split(b"\x00")
            args = [a.decode(errors="replace").strip() for a in args if a]
        except OSError:
            continue

        if not args or "java" not in args[0].lower():
            continue

        # 케이스 A: classpath 토큰에서 log4j JAR 직접 탐지
        for token in args:
            for jar_path in token.split(":"):  # classpath는 콜론으로 구분
                if "log4j" in jar_path.lower() and jar_path.endswith(".jar"):
                    version = _extract_version_from_jar_name(jar_path)
                    if version:
                        return _log4j_entry(version, source=f"pid:{pid_dir.name} {jar_path}")
                    version = _extract_version_from_jar_manifest(jar_path)
                    if version:
                        return _log4j_entry(version, source=f"pid:{pid_dir.name} {jar_path}")

        # 케이스 B: -jar <fat-jar> 패턴 추출 후 JAR 내부 검사
        for i, arg in enumerate(args):
            if arg == "-jar" and i + 1 < len(args):
                fat_jar = args[i + 1]
                result = _inspect_fat_jar_for_log4j(fat_jar, pid=pid_dir.name)
                if result:
                    return result

    return None


def _inspect_fat_jar_for_log4j(jar_path: str, pid: str = "") -> dict | None:
    """
    Fat JAR 내부에서 log4j 버전을 탐지한다.
    우선순위:
      1. BOOT-INF/lib/ 또는 WEB-INF/lib/ 아래 log4j-core-X.Y.Z.jar
      2. META-INF/maven/.../log4j-core/pom.properties 의 version 필드
    """
    if not jar_path or not _safe_exists(Path(jar_path)):
        return None

    source_prefix = f"pid:{pid} " if pid else ""

    listing, _ = _run(["unzip", "-l", jar_path], timeout=15)
    if not listing or "log4j" not in listing.lower():
        return None

    # 1. 중첩 log4j JAR (BOOT-INF/lib/log4j-core-2.14.1.jar 등)
    for line in listing.splitlines():
        m = re.search(
            r"((?:BOOT-INF|WEB-INF)/lib/log4j[^\s/]*\.jar)",
            line,
            re.IGNORECASE,
        )
        if m:
            inner = m.group(1).strip()
            version = _extract_version_from_jar_name(inner)
            if version:
                return _log4j_entry(version, source=f"{source_prefix}{jar_path}!/{inner}")

    # 2. pom.properties 에서 버전 추출
    props, _ = _run(
        ["unzip", "-p", jar_path,
         "BOOT-INF/lib/../../../META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"],
        timeout=5,
    )
    if not props:
        # Spring Boot repackaged 구조의 실제 경로 시도
        props, _ = _run(
            ["unzip", "-p", jar_path,
             "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"],
            timeout=5,
        )
    if props:
        m = re.search(r"version=([\d.]+)", props)
        if m:
            return _log4j_entry(m.group(1), source=f"{source_prefix}{jar_path}![shaded/pom]")

    # 3. 클래스 경로로 버전 추정 (log4j 클래스가 shaded 된 경우)
    #    org/apache/logging/log4j/core/LoggerContext.class 존재 여부만 확인
    if "org/apache/logging/log4j" in listing:
        # 버전 불명이지만 log4j 존재는 확인됨 → "unknown" 으로 기록
        return _log4j_entry("unknown", source=f"{source_prefix}{jar_path}![shaded/class]")

    return None


def _detect_log4j_in_fat_jar() -> dict | None:
    """
    Fat JAR / Shaded JAR 내부에 log4j 클래스(org/apache/logging/log4j)가
    내장된 경우를 탐지한다. 내장 시 log4j2-core 의 Log4jBuildInfo.class
    경로에서 버전을 읽는다.
    """
    # /proc/{pid}/fd 를 통해 실행 중인 JAR 경로 수집
    jar_candidates: list[str] = []
    proc = Path("/proc")
    if _safe_exists(proc):
        for pid_dir in proc.iterdir():
            if not pid_dir.name.isdigit():
                continue
            fd_dir = pid_dir / "fd"
            try:
                for fd in fd_dir.iterdir():
                    try:
                        target = str(fd.resolve())
                        if target.endswith(".jar") and target not in jar_candidates:
                            jar_candidates.append(target)
                    except OSError:
                        continue
            except OSError:
                continue

    # 후보 JAR 내부에서 log4j 클래스 경로 탐색
    for jar_path in jar_candidates:
        if not _safe_exists(Path(jar_path)):
            continue
        listing, _ = _run(["unzip", "-l", jar_path], timeout=10)
        if "log4j" not in listing.lower():
            continue

        # log4j-core 버전 파일 우선 탐색
        # META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties
        props, _ = _run(
            ["unzip", "-p", jar_path,
             "META-INF/maven/org.apache.logging.log4j/log4j-core/pom.properties"],
            timeout=5,
        )
        if props:
            m = re.search(r"version=([\d.]+)", props)
            if m:
                return _log4j_entry(m.group(1), source=f"{jar_path}![shaded]")

        # 중첩 JAR 탐색 (Spring Boot BOOT-INF/lib/)
        for line in listing.splitlines():
            m = re.search(r"(BOOT-INF/lib/log4j[^/\s]*\.jar|WEB-INF/lib/log4j[^/\s]*\.jar)", line, re.IGNORECASE)
            if m:
                inner = m.group(1).strip()
                version = _extract_version_from_jar_name(inner)
                if version:
                    return _log4j_entry(version, source=f"{jar_path}!/{inner}")

    return None


def _log4j_entry(version: str, source: str = "") -> dict:
    entry: dict = {
        "vendor": "apache",
        "product": "log4j",
        "version": version,
        "cpe": f"cpe:2.3:a:apache:log4j:{version}:*:*:*:*:*:*:*",
    }
    if source:
        entry["source_path"] = source
    return entry


def _extract_version_from_jar_name(jar_path: str) -> str | None:
    """
    파일명 패턴 "log4j-core-2.14.1.jar" 에서 버전을 추출한다.
    """
    m = re.search(r"log4j[^/]*?[-_]([\d]+\.[\d]+[\d.]*)\.jar", jar_path, re.IGNORECASE)
    return m.group(1) if m else None


def _extract_version_from_jar_manifest(jar_path: str) -> str | None:
    """
    JAR 내부 META-INF/MANIFEST.MF 의 Implementation-Version 을 읽는다.
    unzip 이 없으면 None 반환.
    """
    stdout, _ = _run(["unzip", "-p", jar_path, "META-INF/MANIFEST.MF"], timeout=5)
    if not stdout:
        return None
    m = re.search(r"Implementation-Version:\s*([\d.]+)", stdout, re.IGNORECASE)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# 탐지 레지스트리
# "vendor:product" → 탐지 함수
# ---------------------------------------------------------------------------

DETECTOR_REGISTRY: dict[str, callable] = {
    "f5:nginx": detect_nginx,
    "apache:log4j": detect_log4j,
}


def get_installed_software(target_keys: set[str] | None = None) -> list[dict]:
    """
    target_keys 가 주어지면 해당 vendor:product 만 탐지한다.
    None 이면 레지스트리에 등록된 모든 소프트웨어를 탐지한다.
    """
    keys_to_check = target_keys if target_keys is not None else set(DETECTOR_REGISTRY.keys())

    software: list[dict] = []
    for key in keys_to_check:
        detector = DETECTOR_REGISTRY.get(key)
        if detector is None:
            print(f"[WARN] 탐지기 없음: {key} — 레지스트리에 추가 필요")
            continue
        result = detector()
        if result:
            software.append(result)
        else:
            print(f"[INFO] 미설치 또는 탐지 실패: {key}")

    return software


# ---------------------------------------------------------------------------
# 메인
# ---------------------------------------------------------------------------

def build_asset_info(args: argparse.Namespace) -> dict:
    # payload 에서 탐지 대상 결정
    target_keys: set[str] | None = None
    if args.payload:
        payload_path = Path(args.payload)
        if not payload_path.exists():
            print(f"[ERROR] payload 파일을 찾을 수 없습니다: {payload_path}")
            raise SystemExit(1)
        target_keys = load_target_keys(payload_path)
        print(f"[INFO] payload 기반 탐지 대상: {sorted(target_keys)}")

    instance_id = get_instance_id()
    hostname = socket.gethostname()
    os_info = get_os_info()
    installed_software = get_installed_software(target_keys)

    return {
        "asset_id": instance_id,
        "hostname": hostname,
        "metadata": {
            "environment": args.environment,
            "network_exposure": args.network_exposure,
            "business_criticality": args.business_criticality,
        },
        "os_info": os_info,
        "installed_software": installed_software,
    }


def main() -> None:
    args = parse_args()
    asset_info = build_asset_info(args)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(asset_info, ensure_ascii=False, indent=2))
    print(f"[OK] 자산 정보 저장 완료: {output_path.resolve()}")
    print(json.dumps(asset_info, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
