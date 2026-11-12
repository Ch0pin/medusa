class Prompt:
    def __init__(self, message):
        self.message = message

    def ask(self):
        """Method to be implemented by subclasses."""
        raise NotImplementedError("Subclasses must implement this method.")


class Alternative(Prompt):
    def __init__(self, message, *args):
        super().__init__(message)
        self.choices = args

    def ask(self):
        answer = input(f"{self.message} ({'/'.join(self.choices)}) ").strip().lower()
        return answer if answer in self.choices else self.ask()


class Numeric(Prompt):
    def __init__(self, message, base=10, lbound=None, ubound=None):
        super().__init__(message)
        self.base = base
        self.lbound = lbound
        self.ubound = ubound

    def ask(self):
        try:
            answer = int(input(f"{self.message} "), self.base)
            if (self.lbound is not None and answer < self.lbound) or (self.ubound is not None and answer > self.ubound):
                return self.ask()
            return answer
        except ValueError:
            return self.ask()


class Boolean(Prompt):
    def __init__(self, message, default=True):
        super().__init__(message)
        self.default = default

    def ask(self):
        prompt = ' (T/f) ' if self.default else ' (t/F) '
        answer = input(self.message + prompt).strip().lower()
        if answer in ['t', 'true']:
            return True
        elif answer in ['f', 'false']:
            return False
        elif answer == '':
            return self.default
        return self.ask()


class Polar(Prompt):
    def __init__(self, message, default=True):
        super().__init__(message)
        self.default = default

    def ask(self):
        prompt = ' (Y/n) ' if self.default else ' (y/N) '
        answer = input(self.message + prompt).strip().lower()
        if answer in ['y', 'yes']:
            return True
        elif answer in ['n', 'no']:
            return False
        elif answer == '':
            return self.default
        return self.ask()


class Open(Prompt):
    def ask(self):
        return input(self.message + ' ').strip()
