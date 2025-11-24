import xml.etree.ElementTree as ET
from typing import Optional, Dict, List
from colorama import Fore, Back, Style, init


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

    def _c(self, text: str, color: str = "", style: str = "", background: str = "") -> str:
        """Helper to apply color, style, and background if enabled."""
        if not self.color:
            return text
        return f"{style}{color}{background}{text}{Style.RESET_ALL}"

    def _extract_components(self, xml_content: str) -> Dict[str, List[Dict[str, str]]]:
        """
        Extract relevant Android components and their names + exported flag.
        Returns a dict: tag -> list of dicts {"name": str, "exported": bool}
        """
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
                name = (
                    elem.attrib.get("{http://schemas.android.com/apk/res/android}name")
                    or elem.attrib.get("name")
                )
                exported_attr = (
                    elem.attrib.get("{http://schemas.android.com/apk/res/android}exported")
                    or elem.attrib.get("exported")
                )
                exported = exported_attr and exported_attr.lower() == "true"

                if name:
                    components[tag].append({"name": name, "exported": exported})

        return components

    def _diff_sets(self, old_list: List[Dict[str, str]], new_list: List[Dict[str, str]]) -> List[str]:
        """
        Return added and removed entries with color.
        Exported components are highlighted with cyan background.
        """
        old_set = {c["name"]: c["exported"] for c in old_list}
        new_set = {c["name"]: c["exported"] for c in new_list}

        added_names = sorted(set(new_set.keys()) - set(old_set.keys()))
        removed_names = sorted(set(old_set.keys()) - set(new_set.keys()))

        lines = []

        for name in added_names:
            exported = new_set[name]
            if exported:
                text = self._c(f"+ Added: {name} (exported)", Fore.GREEN, Style.BRIGHT, Back.WHITE)
            else:
                text = self._c(f"+ Added: {name}", Fore.GREEN)
            lines.append(text)

        for name in removed_names:
            exported = old_set[name]
            if exported:
                text = self._c(f"- Removed: {name} (exported)", Fore.RED, Style.BRIGHT, Back.WHITE)
            else:
                text = self._c(f"- Removed: {name}", Fore.RED)
            lines.append(text)

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
                report_lines.append(
                    self._c("No relevant component changes detected.", Fore.LIGHTBLACK_EX)
                )

        return "\n".join(report_lines)

class ManifestParser:
    """
    Parses an AndroidManifest.xml string and allows retrieving elements by name.
    """

    def __init__(self, manifest_xml: str):
        self.manifest_xml = manifest_xml
        try:
            self.root = ET.fromstring(manifest_xml)
        except ET.ParseError as e:
            raise ValueError(f"Invalid manifest XML: {e}")

    def get_manifest_attribute(self, attr_name: str) -> Optional[str]:
        ns = "{http://schemas.android.com/apk/res/android}"
        return self.root.attrib.get(f"{ns}{attr_name}") or self.root.attrib.get(attr_name)

    def get_elements(self, tag_name: str) -> List[ET.Element]:
        """
        Returns a list of all elements matching the given tag name.

        Example:
            parser.get_elements("activity")
        """
        # Find all elements in the tree with the given tag
        return list(self.root.iter(tag_name))

    def get_element_by_name(self, tag_name: str, name: str) -> Optional[ET.Element]:
        """
        Returns the first element matching both tag name and android:name (or name) attribute.
        Returns None if not found.

        Example:
            parser.get_element_by_name("activity", "com.example.MainActivity")
        """
        namespace = "{http://schemas.android.com/apk/res/android}name"

        for elem in self.root.iter(tag_name):
            elem_name = (
                elem.attrib.get(namespace)
                or elem.attrib.get("name")
                or elem.attrib.get("android:name")
            )
            if elem_name == name:
                return elem
        return None

    def list_tag_names(self) -> List[str]:
        """
        Returns a unique list of all tag names present in the manifest.
        """
        return sorted({elem.tag for elem in self.root.iter()})