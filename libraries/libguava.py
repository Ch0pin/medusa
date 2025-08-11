import fnmatch
import hashlib
import io
import json
import logging
import re
import shutil
import subprocess
import threading

# Third-party imports
from androguard.core import apk
from androguard import util
from apkInspector.indicators import apk_tampering_check

# Local application/library specific imports
from libraries.db import apk_db
from libraries.IntentFilter import IntentFilter
from libraries.logging_config import setup_logging
from libraries.Questions import Polar



logging.getLogger().handlers = []  
setup_logging() 
logger = logging.getLogger(__name__)


NS_ANDROID_URI = "http://schemas.android.com/apk/res/android"
NS_ANDROID = '{http://schemas.android.com/apk/res/android}'

protection_flags_to_attributes = {
        "0x00000000": "normal",
        "0x00000001": "dangerous",
        "0x00000002": "signature",
        "0x00000003": "signature or system",
        "0x00000004": "internal",
        "0x00000010": "privileged",
        "0x00000020": "development",
        "0x00000040": "appop",
        "0x00000080": "pre23",
        "0x00000100": "installer",
        "0x00000200": "verifier",
        "0x00000400": "preinstalled",
        "0x00000800": "setup",
        "0x00001000": "instant",
        "0x00002000": "runtime only",
        "0x00004000": "oem",
        "0x00008000": "vendor privileged",
        "0x00010000": "system text classifier",
        "0x00020000": "wellbeing",
        "0x00040000": "documenter",
        "0x00080000": "configurator",
        "0x00100000": "incident report approver",
        "0x00200000": "app predictor",
        "0x00400000": "module",
        "0x00800000": "companion",
        "0x01000000": "retail demo",
        "0x02000000": "recents",
        "0x04000000": "role",
        "0x08000000": "known signer"
        }


# Silence Loguru from Androguard
util.set_log("ERROR")


class Guava:
    filter_list = {}

    def __init__(self, db_instance):
        self.application_database = db_instance
        filter_list = {}

    def sha256sum(self, filename):
        h = hashlib.sha256()
        b = bytearray(128 * 1024)
        mv = memoryview(b)
        with open(filename, 'rb', buffering=0) as f:
            for n in iter(lambda: f.readinto(mv), 0):
                h.update(mv[:n])
        return h.hexdigest()

    def sha256Exists(self, sha):
        sql = f"""SELECT name from Application WHERE sha256='{sha}'"""
        return self.application_database.query_db(sql)

    def extractIntentFilters(self, filters, obj):
        filterList = []
        name = obj.get(NS_ANDROID + "name")
        filters = obj.findall("intent-filter")
        for filter in filters:
            intentFilter = IntentFilter()
            intentFilter.componentName = name
            if len(filter.findall("action")) > 0:
                for action in filter.findall("action"):
                    intentFilter.addAction(action.get(NS_ANDROID + "name"))
            if len(filter.findall("category")) > 0:
                for category in filter.findall("category"):
                    intentFilter.addCategory(category.get(NS_ANDROID + "name"))
            if len(filter.findall("data")) > 0:
                for data in filter.findall("data"):
                    if data.get(NS_ANDROID + "scheme") is not None:
                        intentFilter.addData("scheme:" + data.get(NS_ANDROID + "scheme"))
                    if data.get(NS_ANDROID + "host") is not None:
                        intentFilter.addData("host:" + data.get(NS_ANDROID + "host"))
                    if data.get(NS_ANDROID + "port") is not None:
                        intentFilter.addData("port:" + data.get(NS_ANDROID + "port"))
                    if data.get(NS_ANDROID + "path") is not None:
                        intentFilter.addData("path:" + data.get(NS_ANDROID + "path"))
                    if data.get(NS_ANDROID + "pathPattern") is not None:
                        intentFilter.addData("pathPattern:" + data.get(NS_ANDROID + "pathPattern"))
                    if data.get(NS_ANDROID + "pathPrefix") is not None:
                        intentFilter.addData("pathPrefix:" + data.get(NS_ANDROID + "pathPrefix"))
                    if data.get(NS_ANDROID + "mimeType") is not None:
                        intentFilter.addData("mimeType:" + data.get(NS_ANDROID + "mimeType"))
            filterList.append(intentFilter)
        self.filter_list[name] = filterList

    def fill_activities(self, application, sha256):

        for activity in application.findall("activity"):
            activityName = activity.get(NS_ANDROID + "name")
            enabled = activity.get(NS_ANDROID + "enabled")
            exported = activity.get(NS_ANDROID + "exported")
            autoRemoveFromRecents = activity.get(NS_ANDROID + "autoRemoveFromRecents")
            excludeFromRecents = activity.get(NS_ANDROID + "excludeFromRecents")
            noHistory = activity.get(NS_ANDROID + "noHistory")
            permission = activity.get(NS_ANDROID + "permission")

            if len(activity.findall("intent-filter")) > 0:
                if exported != 'false':
                    exported = "true (intent filter)"

                filters = activity.findall("intent-filter")
                self.extractIntentFilters(filters, activity)

            activity_attribs = (
                sha256, activityName, enabled, exported, autoRemoveFromRecents, excludeFromRecents, noHistory,
                permission)
            self.application_database.update_activities(activity_attribs)

    def fill_activity_alias(self, application, sha256):

        for activity_alias in application.findall("activity-alias"):
            aliasname = activity_alias.get(NS_ANDROID + "name")
            enabled = activity_alias.get(NS_ANDROID + "enabled")
            exported = activity_alias.get(NS_ANDROID + "exported")
            permission = activity_alias.get(NS_ANDROID + "permission")
            targetActivity = activity_alias.get(NS_ANDROID + "targetActivity")

            if len(activity_alias.findall("intent-filter")) > 0:
                if exported != 'false':
                    exported = "true (intent filter)"
                filters = activity_alias.findall("intent-filter")
                self.extractIntentFilters(filters, activity_alias)

            activity_alias_attributes = (sha256, aliasname, enabled, exported, permission, targetActivity)
            self.application_database.update_activity_alias(activity_alias_attributes)

    def fill_application_attributes(self, parsed_apk, sha256, application, original_filename):
        try:

            try:
                tampering = self.detect_tampering(parsed_apk)
            except Exception as e:
                logger.error(f"Error detecting tampering: {e}")
                tampering = "N/A"

            arsc = parsed_apk.get_android_resources()
            app_attributes = (sha256, parsed_apk.get_app_name(), parsed_apk.get_package(),
                            parsed_apk.get_androidversion_code(), parsed_apk.get_androidversion_name(),
                            parsed_apk.get_min_sdk_version(), parsed_apk.get_target_sdk_version(),
                            parsed_apk.get_max_sdk_version(), '|'.join(parsed_apk.get_permissions()),
                            ' '.join(parsed_apk.get_libraries())) + (
                                application.get(NS_ANDROID + "debuggable"), application.get(NS_ANDROID + "allowBackup"),
                                parsed_apk.get_android_manifest_axml().get_xml(),
                                arsc.get_string_resources(arsc.get_packages_names()[0]), original_filename,
                                tampering, self.detect_framework(parsed_apk))
            self.application_database.update_application(app_attributes)
        except Exception as e:
            logger.error(e)
            

    def fill_permissions(self, parsed_apk, sha256):
        app_declared_permissions = parsed_apk.get_declared_permissions_details()
        app_permissions = parsed_apk.get_details_permissions()
        for permission in app_permissions:
            custom = False
            for c_permission in app_declared_permissions:
                if permission == c_permission and not permission.startswith(("android.permission.", "com.google.")):
                    custom = True
                    level = app_declared_permissions[permission]['protectionLevel']
                    if level == 'None': 
                        level = "0x00000000"
                    entry = (sha256, permission, protection_flags_to_attributes[level], ) + tuple(app_permissions[permission][1:]) 
            if not custom:
                entry = (sha256, permission,) + tuple(app_permissions[permission])
            self.application_database.update_permissions(entry)
            

    def fill_providers(self, application, sha256):

        for provider in application.findall("provider"):
            providername = provider.get(NS_ANDROID + "name")
            enabled = provider.get(NS_ANDROID + "enabled")
            exported = provider.get(NS_ANDROID + "exported")
            grantUriPermissions = provider.get(NS_ANDROID + "grantUriPermissions")
            permission = provider.get(NS_ANDROID + "permission")
            process = provider.get(NS_ANDROID + "process")
            readPermission = provider.get(NS_ANDROID + "readPermission")
            writePermission = provider.get(NS_ANDROID + "writePermission")
            authorities = provider.get(NS_ANDROID + "authorities")
            provider_attribs = (
                sha256, providername, enabled, exported, grantUriPermissions, permission, process, readPermission,
                writePermission, authorities)
            self.application_database.update_providers(provider_attribs)

    def fill_receivers(self, application, sha256):

        for receiver in application.findall("receiver"):
            receivername = receiver.get(NS_ANDROID + "name")
            enabled = receiver.get(NS_ANDROID + "enabled")
            exported = receiver.get(NS_ANDROID + "exported")
            permission = receiver.get(NS_ANDROID + "permission")
            process = receiver.get(NS_ANDROID + "process")

            if len(receiver.findall("intent-filter")) > 0:
                if exported != 'false':
                    exported = "true (intent filter)"
                filters = receiver.findall("intent-filter")
                self.extractIntentFilters(filters, receiver)

            receiver_attribs = (sha256, receivername, enabled, exported, permission, process)
            self.application_database.update_receivers(receiver_attribs)

    def fill_secrets(self, apkfile: str, sha256: str):
        logger.info(f"Extracting secrets in the background: {apkfile} (sha256: {sha256})")
        try:
            proc = subprocess.Popen(
                ["trufflehog", "filesystem", apkfile, "-j"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1
            )

            entries = []
            seen = set()

            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.strip()
                if not line:
                    continue

                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                # Skip log-only lines
                if "DetectorName" not in obj:
                    continue

                # Extract file/line if available
                file_path = None
                line_no = None
                try:
                    fs = obj.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                    file_path = fs.get("file")
                    line_no = fs.get("line")
                except Exception:
                    pass

                # Prefer RawV2 if non-empty, else Raw
                raw_val = obj.get("RawV2") or obj.get("Raw")

                # Deduplicate by unique signature
                dedupe_key = (obj.get("DetectorName"), raw_val, file_path, line_no)
                if dedupe_key in seen:
                    continue
                seen.add(dedupe_key)

                # Build entry
                entry = {
                    "DetectorName": obj.get("DetectorName"),
                    "DetectorDescription": obj.get("DetectorDescription"),
                    "DecoderName": obj.get("DecoderName"),
                    "Verified": obj.get("Verified", False),
                    "Raw": raw_val,
                    "File": file_path,
                    "Line": line_no
                }

                # Include ExtraData if not null/empty
                extra_data = obj.get("ExtraData")
                if extra_data:
                    entry["ExtraData"] = extra_data

                # Include StructuredData if not null
                structured_data = obj.get("StructuredData")
                if structured_data:
                    entry["StructuredData"] = structured_data

                entries.append(entry)

            # Finish reading process
            _, stderr_data = proc.communicate()
            if proc.returncode not in (0, 2):
                logger.warning(f"trufflehog exit code {proc.returncode}. stderr: {stderr_data.strip()}")

            # Store results in DB
            secret_json = json.dumps(entries, indent=2, ensure_ascii=False)
            self.application_database.insert_secret((sha256, secret_json))
            logger.info(f"Secrets extracted from {apkfile} (sha256: {sha256}). Found {len(entries)} entries.")

        except Exception as e:
            self.application_database.insert_secret((sha256, ""))
            logger.error(f"Error extracting secrets from {apkfile} (sha256: {sha256}): {e}")

    def fill_services(self, application, sha256):

        for service in application.findall("service"):
            servicename = service.get(NS_ANDROID + "name")
            enabled = service.get(NS_ANDROID + "enabled")
            exported = service.get(NS_ANDROID + "exported")
            foregroundServiceType = service.get(NS_ANDROID + "foregroundServiceType")
            permission = service.get(NS_ANDROID + "permission")
            process = service.get(NS_ANDROID + "process")

            if len(service.findall("intent-filter")) > 0:
                if exported != 'false':
                    exported = "true (intent filter)"
                filters = service.findall("intent-filter")
                self.extractIntentFilters(filters, service)

            service_attribs = (sha256, servicename, enabled, exported, foregroundServiceType, permission, process)
            self.application_database.update_services(service_attribs)

    def full_analysis(self, apkfile, print_info=True):

        app_sha256 = self.sha256sum(apkfile)

        logger.info(f"[+] Analyzing apk with SHA256:{app_sha256}")
        apk_r = apk.APK(apkfile)            
        manifest = apk_r.get_android_manifest_axml().get_xml_obj()
        application = manifest.findall("application")[0]
        if print_info:
            logger.info("[+] Analysis finished.")
            logger.info("[+] Filling up the database....")
        self.filter_list = {}
        self.fill_application_attributes(apk_r, app_sha256, application, apkfile)
        self.fill_permissions(apk_r, app_sha256)
        if shutil.which("trufflehog") is None:
            logger.warning("trufflehog is not installed. Secrets will not be extracted.")
            self.application_database.insert_secret((app_sha256, ""))
        else:
            worker_thread = threading.Thread(target=self.fill_secrets, args=(apkfile, app_sha256))
            worker_thread.start()
        #self.fill_secrets(apkfile, app_sha256)
        self.fill_activities(application, app_sha256)
        self.fill_services(application, app_sha256)
        self.fill_providers(application, app_sha256)
        self.fill_receivers(application, app_sha256)
        self.fill_activity_alias(application, app_sha256)
        self.fill_intent_filters(app_sha256)
        if print_info:
            logger.info("[+] Database Ready !")

    def fill_intent_filters(self, sha256):
        for filter in self.filter_list:
            objlist = self.filter_list[filter]
            for item in objlist:
                filter_attribs = (
                    sha256, filter, '|'.join(item.actionList), '|'.join(item.categoryList), '|'.join(item.dataList))
                self.application_database.update_intent_filters(filter_attribs)

    def insert_note(self, sha256, note):
        note = (sha256, note)
        self.application_database.insert_note(note)

    def update_note(self, index, note):
        self.application_database.update_note(index, note)

    def delete_note(self, index):
        self.application_database.delete_note(index)
    
    def detect_framework(self, parsed_apk):
        assets = parsed_apk.get_files()
        for entry in assets:
            if 'index.android.bundle' in entry:
                return 'React Native'
            elif fnmatch.fnmatch(entry, '*cordova*.js') or ('www/index.html' in assets and 'www/js/index.js' in assets):
                return 'Ionic Cordova'
            elif fnmatch.fnmatch(entry, '*libflutter.so'):
                for fEntry in assets:
                    if fnmatch.fnmatch(fEntry, '*libapp.so'):
                        return 'Flutter'
            elif fnmatch.fnmatch(entry, '*assemblies.manifest'):
                for xEntry in assets:
                    if fnmatch.fnmatch(xEntry, '*assemblies.blob'):
                        return 'Xamarin'   
        return 'None Detected'


    def detect_tampering(self, parsed_apk):
        tamperings = apk_tampering_check(io.BytesIO(parsed_apk.get_raw()), False)
        tampering_types = []

        if tamperings.get("zip tampering", 0):
            tampering_types.append("ZIP")

        if tamperings.get('manifest tampering', 0):
            tampering_types.append("MANIFEST")

        return ' | '.join(tampering_types) if tampering_types else "None"
