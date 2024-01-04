import json


class Module:
    def __init__(self, fullPath, name, description, useCase, code):
        self.path = fullPath
        self.Name = name
        self.Description = description
        self.Help = useCase
        self.Code = code

    def save(self):
        with open(self.path, 'w') as mod:
            mod.write(json.dumps({ field : value for field, value in self.__dict__.items() if field != 'path' }, indent=4))

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

    def _parseModuleFile(self, modulePath):
        with open(modulePath, 'r', encoding='utf-8') as mod:
            contents = json.loads(mod.read(), strict=False)
        mod = Module(modulePath, contents['Name'], contents['Description'], contents['Help'], contents['Code'])
        self.categories.add(mod.getCategory())
        return mod

    def add(self, modulePath):
        self.available.append(self._parseModuleFile(modulePath))

    def compile(self):
        code = ''
        for mod in self.staged:
            code += mod.Code + '\n'
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
                        print('Module {} already added !'.format(mod.Name))
                        alread_added = True                   
        if added: 
            return
        else:
            if "scratchpad" not in moduleName and not alread_added:
                print('Module {} not found!'.format(moduleName))

    def stage_verbadim(self,moduleName):
        if moduleName not in [mod.Name for mod in self.staged]:
            for mod in self.available:
                if mod.Name == moduleName:
                    self.staged.append(mod)
                    return
            print('Module {} not found!'.format(moduleName))

    def unstage(self, moduleName):
        
        tmp = len(self.staged)

        for mod in self.staged:             #check for exact name first 
            if moduleName == mod.Name:
                self.staged.remove(mod)
                return True

        self.staged = [mod for mod in self.staged if not mod.Name.startswith(moduleName)]   #remove all starting with modulaname

        if tmp == len(self.staged):
            return False
        return True
