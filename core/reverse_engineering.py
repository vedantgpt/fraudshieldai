import os
import subprocess
import platform
from typing import Dict


class ReverseEngineeringEngine:
    """Decompile APK with bundled JADX; fallback to androguard manifest extraction."""

    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self.jadx_dir = os.path.join(base_dir, "static_tools", "jadx", "bin")

    def decompile(self, apk_path: str, output_dir: str) -> dict:
        os.makedirs(output_dir, exist_ok=True)
        resources_path = os.path.join(output_dir, "resources")
        sources_path = os.path.join(output_dir, "sources")
        if os.path.isdir(resources_path) and os.path.isdir(sources_path):
            return {"success": True, "path": output_dir, "cached": True}

        is_windows = platform.system() == "Windows"
        jadx_executable = "jadx.bat" if is_windows else "jadx"
        jadx_path = os.path.join(self.jadx_dir, jadx_executable)

        if not os.path.isfile(jadx_path):
            return self._fallback(apk_path, output_dir, f"JADX not found at {jadx_path}")

        try:
            result = subprocess.run(
                [jadx_path, apk_path, "-d", output_dir],
                capture_output=True, text=True, check=True
            )
            if not os.path.isfile(os.path.join(resources_path, "AndroidManifest.xml")):
                return self._fallback(apk_path, output_dir, "JADX completed but manifest not found")
            return {"success": True, "path": output_dir, "stdout": result.stdout}
        except subprocess.CalledProcessError as e:
            return self._fallback(apk_path, output_dir, e.stderr or e.stdout)
        except FileNotFoundError:
            return self._fallback(apk_path, output_dir, f"jadx executable not found: {jadx_path}")

    def _fallback(self, apk_path: str, output_dir: str, error: str) -> Dict:
        """Extract at least AndroidManifest.xml using androguard so static analysis can proceed."""
        try:
            from androguard.core.bytecodes.apk import APK
            from lxml import etree
            apk = APK(apk_path)
            manifest = apk.get_android_manifest_xml()
            if manifest is not None:
                resources_path = os.path.join(output_dir, "resources")
                os.makedirs(resources_path, exist_ok=True)
                manifest_path = os.path.join(resources_path, "AndroidManifest.xml")
                etree.ElementTree(manifest).write(
                    manifest_path, encoding="utf-8", xml_declaration=True, pretty_print=True
                )
                return {
                    "success": True,
                    "path": output_dir,
                    "fallback": True,
                    "error": error,
                    "manifest_extracted": True,
                }
        except Exception as exc:
            error += f"; androguard fallback also failed: {exc}"
        return {"success": False, "error": error, "path": output_dir}
