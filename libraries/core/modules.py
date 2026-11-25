import json
import hashlib
import logging
import os
from pathlib import Path

from libraries.logging_config import setup_logging


logging.getLogger().handlers = []
setup_logging()
logger = logging.getLogger(__name__)


class ModuleLoadError(ValueError):
    def __init__(self, path, code, message, **details):
        self.details = {"path": str(path), "code": code, "message": message, **details}
        super().__init__(f"{path}: {message}")


def configured_module_roots(base_directory, additional_roots=None):
    """The built-in root always comes first; relative roots use the checkout."""
    base = Path(base_directory).resolve()
    extra = (os.environ.get('MEDUSA_MODULE_ROOTS', '').split(os.pathsep)
             if additional_roots is None else additional_roots)
    roots = [base / 'modules']
    for value in extra:
        if not str(value).strip():
            continue
        path = Path(value).expanduser()
        roots.append(path if path.is_absolute() else base / path)
    return list(dict.fromkeys(str(path.resolve()) for path in roots))

class Module:
    def __init__(self, fullPath, name, description, useCase, code, options = None):
        self.path = fullPath
        self.Name = name
        self.Description = description
        self.Help = useCase
        self.Code = code
        self.Options = options

    def save(self):
        with open(self.path, 'w') as mod:
            mod.write(json.dumps({field: value for field, value in self.__dict__.items() if field != 'path'}, indent=4))

    def getCategory(self):
        category = self.Name.split('/')
        if len(category) == 2:
            return category[0]
        return 'uncategorized'


class ModuleManager:
    def __init__(self):
        self.available = []
        self.staged = []
        self.categories = set()
        self.roots = []
        self.imported_paths = []
        self.load_errors = []
        self.sources = {}
        self.retained_staged = []

    def _read_module(self, module_path):
        path = Path(module_path).expanduser().absolute()
        if path.suffix not in {'.med', '.imed'}:
            raise ModuleLoadError(path, 'invalid_extension', 'expected a .med or .imed file')
        try:
            with path.open('rb') as stream:
                raw = stream.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise ModuleLoadError(path, 'file_too_large', 'module exceeds 16 MiB')
            contents = json.loads(raw.decode('utf-8'), strict=False)
        except json.JSONDecodeError as exc:
            raise ModuleLoadError(path, 'invalid_json', exc.msg, line=exc.lineno, column=exc.colno) from exc
        except ModuleLoadError:
            raise
        except (OSError, UnicodeError, ValueError) as exc:
            raise ModuleLoadError(path, 'read_error', str(exc)) from exc
        if not isinstance(contents, dict):
            raise ModuleLoadError(path, 'invalid_schema', 'module must be a JSON object')
        for field in ('Name', 'Description', 'Help', 'Code'):
            if not isinstance(contents.get(field), str):
                raise ModuleLoadError(path, 'invalid_schema', f'{field} must be a string')
        name = contents['Name']
        if not name or name != name.strip() or any(ord(char) < 32 for char in name):
            raise ModuleLoadError(path, 'invalid_name', 'Name must be nonempty and contain no control characters or surrounding whitespace')
        options = contents.get('Options')
        if options is not None and not isinstance(options, (dict, list)):
            raise ModuleLoadError(path, 'invalid_schema', 'Options must be an object, list or null')
        module = Module(str(path), name, contents['Description'], contents['Help'], contents['Code'], options)
        try:
            canonical = str(path.resolve())
        except (OSError, RuntimeError) as exc:
            raise ModuleLoadError(path, 'invalid_path', str(exc)) from exc
        return module, {'path': str(path), 'canonical_path': canonical, 'source_sha256': hashlib.sha256(raw).hexdigest()}

    def _parseModuleFile(self, modulePath):
        try:
            mod, metadata = self._read_module(modulePath)
            self.sources[mod.path] = metadata
            return mod
        except ModuleLoadError as e:
            self.load_errors.append(e.details)
            logger.warning(f'Error parsing module file {modulePath}: {e}')
            return None

    def add(self, modulePath):
        previous_source = self.sources.get(str(Path(modulePath).expanduser().absolute()))
        mod = self._parseModuleFile(modulePath)
        if mod is None:
            return None
        existing = next((item for item in self.available if item.Name == mod.Name), None)
        if existing:
            if Path(existing.path).resolve() != Path(mod.path).resolve():
                error = ModuleLoadError(mod.path, 'duplicate_name', f'Name already loaded: {mod.Name}',
                                        name=mod.Name, existing_path=existing.path)
                self.load_errors.append(error.details)
                logger.warning(str(error))
                return None
            if existing.path == mod.path and previous_source is not None:
                self.sources[mod.path] = previous_source
            return existing
        self.available.append(mod)
        self.categories.add(mod.getCategory())
        return mod

    def import_file(self, module_path, *, suffix='.med'):
        """Load one validated file without executing JavaScript or replacing staged work."""
        path = Path(module_path).expanduser().absolute()
        if path.suffix != suffix:
            raise ModuleLoadError(path, 'wrong_platform', f'expected a {suffix} module')
        mod, metadata = self._read_module(path)
        old = next((item for item in self.available if item.Name == mod.Name), None)
        if old and Path(old.path).resolve() != Path(mod.path).resolve():
            raise ModuleLoadError(path, 'duplicate_name', f'Name already loaded: {mod.Name}',
                                  name=mod.Name, existing_path=old.path)
        same_content = old is not None and all(getattr(old, key) == getattr(mod, key) for key in
                                               ('Name', 'Description', 'Help', 'Code', 'Options'))
        if old and same_content:
            self.sources[old.path] = dict(metadata, path=old.path)
            if old.path not in self.imported_paths:
                self.imported_paths.append(old.path)
            return old
        if old and old.Name == 'scratchpad':
            raise ModuleLoadError(path, 'reserved_module', 'preserve scratchpad edits; use the scratchpad editor or MCP overlay')
        if old in self.staged:
            raise ModuleLoadError(path, 'staged_module', 'unstage this module before importing a replacement', name=mod.Name)
        if old:
            self.available[self.available.index(old)] = mod
        else:
            self.available.append(mod)
        self.sources[mod.path] = metadata
        self.categories = {item.getCategory() for item in self.available}
        if mod.path not in self.imported_paths:
            self.imported_paths.append(mod.path)
        return mod

    def refresh(self, roots, *, suffix='.med', preserve_names=()):
        """Build a new index first, then swap it while retaining staged objects."""
        candidate = ModuleManager()
        candidate.roots = list(dict.fromkeys(str(Path(root).expanduser().resolve()) for root in roots))
        candidate.imported_paths = list(self.imported_paths)
        seen = set()
        def add(path):
            try:
                canonical = str(Path(path).resolve())
            except (OSError, RuntimeError, ValueError) as exc:
                candidate.load_errors.append({'path': str(path), 'code': 'invalid_path', 'message': str(exc)})
                return
            if canonical not in seen:
                seen.add(canonical)
                candidate.add(path)
        for root in candidate.roots:
            if not Path(root).is_dir():
                candidate.load_errors.append({'path': root, 'code': 'invalid_root', 'message': 'module root is not a directory'})
                logger.warning(f'Module root is not a directory: {root}')
                continue
            def walk_error(error):
                candidate.load_errors.append({'path': error.filename, 'code': 'read_error', 'message': str(error)})
            # Preserve the original built-in traversal order. Explicit symlink
            # roots resolve above; nested directory symlinks are not followed.
            for folder, directories, files in os.walk(root, onerror=walk_error):
                for directory in directories:
                    path = Path(folder) / directory
                    if path.is_symlink():
                        candidate.load_errors.append({'path': str(path), 'code': 'symlink_directory_skipped',
                                                      'message': 'configure this directory as an explicit module root'})
                for filename in files:
                    if filename.endswith(suffix):
                        add(Path(folder) / filename)
        for path in candidate.imported_paths:
            add(path)
        protected = set(preserve_names) | {mod.Name for mod in self.staged} | {'scratchpad'}
        for old in self.available:
            if old.Name not in protected:
                continue
            fresh = next((mod for mod in candidate.available if mod.Name == old.Name), None)
            changed = fresh is None or any(getattr(old, key) != getattr(fresh, key) for key in
                                          ('path', 'Name', 'Description', 'Help', 'Code', 'Options'))
            if fresh is None:
                candidate.available.append(old)
            else:
                candidate.available[candidate.available.index(fresh)] = old
            disk_metadata = candidate.sources.get(old.path, {})
            candidate.sources[old.path] = dict(self.sources.get(old.path, {'path': old.path}),
                                               disk_sha256=disk_metadata.get('source_sha256'), preserved=True)
            if changed:
                candidate.retained_staged.append({'name': old.Name, 'path': old.path,
                                                  'reason': 'source_or_staged_content_differs' if fresh else 'source_missing_or_invalid'})
        self.available = candidate.available
        self.categories = {mod.getCategory() for mod in self.available}
        self.roots, self.imported_paths = candidate.roots, candidate.imported_paths
        self.sources, self.load_errors = candidate.sources, candidate.load_errors
        self.retained_staged = candidate.retained_staged
        return self.catalog_status()

    def catalog_status(self):
        return {'count': len(self.available), 'roots': list(self.roots), 'imported_paths': list(self.imported_paths),
                'load_errors': list(self.load_errors[:100]), 'load_error_count': len(self.load_errors),
                'errors_truncated': len(self.load_errors) > 100, 'retained_staged': list(self.retained_staged)}

    def compile(self):
        code = ''
        for mod in self.staged:
            module_name = json.dumps(mod.Name)
            code += f'''
    try {{
        // Module: {mod.Name}
    {mod.Code}
    }} catch (error) {{
        colorLog("[module failed] " + {module_name}, {{ c: Color.Red }});
        console.log(error && error.stack ? error.stack : error);
    }}
    '''
        return code

    def findModule(self, pattern):
        return [mod.Name for mod in self.available if pattern.casefold() in mod.Name.casefold()]

    def getModule(self, name):
        return [mod for mod in self.available if mod.Name == name][0]

    def get_number_of_modules(self):
        return len(self.available)

    def reset(self):
        self.staged = []

    def stage(self, moduleName):
        added = False
        alread_added = False

        for mod in self.available:
            if mod.Name == moduleName and mod not in self.staged:
                self.staged.append(mod)
                added = True
                break

            elif mod.Name.startswith(moduleName):
                if mod not in self.staged:
                    self.staged.append(mod)
                    added = True
                else:
                    if moduleName != 'scratchpad':
                        print(f'Module {mod.Name} already added !')
                        alread_added = True
        if added:
            return
        else:
            if "scratchpad" not in moduleName and not alread_added:
                print(f'Module {moduleName} not found!')

    def stage_verbadim(self, moduleName):
        if moduleName not in [mod.Name for mod in self.staged]:
            for mod in self.available:
                if mod.Name == moduleName:
                    self.staged.append(mod)
                    return
            print(f'Module {moduleName} not found!')

    def unstage(self, moduleName):
        tmp = len(self.staged)

        for mod in self.staged:  # check for exact name first
            if moduleName == mod.Name:
                self.staged.remove(mod)
                return True

        self.staged = [mod for mod in self.staged if not mod.Name.startswith(moduleName)]  # remove all starting with modulaname

        if tmp == len(self.staged):
            return False
        return True
