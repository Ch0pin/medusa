import xml.etree.ElementTree as ET
from typing import Dict, List
from colorama import Fore, Style, init


class ManifestDiff:
    """
    Compares multiple AndroidManifest.xml versions for one package and
    produces a colorized summary of added/removed components
    (activities, activity-aliases, services, receivers, providers).
    """

    COMPONENT_TAGS = {
        "activity": "activity",
        "activity-alias": "activity-alias",
        "service": "service",
        "receiver": "receiver",
        "provider": "provider",
    }

    def __init__(self, package_name: str, versions: Dict[int, str], color: bool = True):
        """
        :param package_name: Package name (e.g. com.example.app)
        :param versions: Dict mapping version_code -> manifest XML string
        :param color: Whether to colorize output using colorama (default: True)
        """
        self.package_name = package_name
        self.versions = dict(sorted(versions.items(), key=lambda kv: kv[0]))
        self.color = color
        init(autoreset=True)

    def _c(self, text: str, color: str) -> str:
        """Helper to apply color only if enabled."""
        return f"{color}{text}{Style.RESET_ALL}" if self.color else text

    def _extract_components(self, xml_content: str) -> Dict[str, List[str]]:
        """Extract relevant Android components and their names."""
        components = {tag: [] for tag in self.COMPONENT_TAGS.keys()}

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError:
            return components  # skip malformed XMLs

        app = root.find("application")
        if app is None:
            return components

        for tag in self.COMPONENT_TAGS.keys():
            for elem in app.findall(tag):
                name = elem.attrib.get("{http://schemas.android.com/apk/res/android}name")
                if name:
                    components[tag].append(name)

        return components

    def _diff_sets(self, old_set: List[str], new_set: List[str]) -> List[str]:
        """Return added and removed entries with color."""
        old, new = set(old_set), set(new_set)
        added = sorted(new - old)
        removed = sorted(old - new)

        lines = []
        for item in added:
            lines.append(self._c(f"+ Added: {item}", Fore.GREEN))
        for item in removed:
            lines.append(self._c(f"- Removed: {item}", Fore.RED))
        return lines

    def generate_diff_report(self) -> str:
        """Generate a version-by-version component change report."""
        version_codes = list(self.versions.keys())
        if len(version_codes) < 2:
            return f"[{self.package_name}] Not enough versions to diff."

        report_lines = [
            self._c(f"===== Package: {self.package_name} =====", Fore.CYAN)
        ]

        for i in range(1, len(version_codes)):
            old_ver, new_ver = version_codes[i - 1], version_codes[i]
            old_components = self._extract_components(self.versions[old_ver])
            new_components = self._extract_components(self.versions[new_ver])

            report_lines.append(
                f"\n{self._c(f'=== Diff: v{old_ver} → v{new_ver} ===', Fore.CYAN)}"
            )

            total_changes = 0
            for tag in self.COMPONENT_TAGS.keys():
                diff_lines = self._diff_sets(old_components[tag], new_components[tag])
                if diff_lines:
                    report_lines.append(self._c(f"\n[{tag}]", Fore.YELLOW))
                    report_lines.extend(diff_lines)
                    total_changes += len(diff_lines)

            if total_changes == 0:
                report_lines.append(self._c("No relevant component changes detected.", Fore.LIGHTBLACK_EX))

        return "\n".join(report_lines)
