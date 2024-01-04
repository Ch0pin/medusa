class Alternative:
	def __init__(self, message, *args):
		self.message = message
		self.choices = args

	def ask(self):
		answer = input(self.message + ' (' + '/'.join(choice for choice in self.choices) + ') ')
		if answer.lower() not in self.choices:
			return self.ask()
		return answer

class Numeric:
	def __init__(self, message, base=10, lbound=None, ubound=None):
		self.message = message
		self.base = base
		self.lbound = lbound
		self.ubound = ubound

	def ask(self):
		try:
			answer = int(input(self.message + ' '), self.base)
			if self.lbound is not None:
				if answer < self.lbound:
					return self.ask()
			if self.ubound is not None:
				if answer > self.ubound:
					return self.ask()
			return answer
		except ValueError:
			return self.ask()


class Polar:
	def __init__(self, message, default=True):
		self.message = message
		self.default = default

	def ask(self):
		answer = input(self.message + (' (Y/n) ' if self.default else ' (y/N) ')).strip()
		if answer.lower() == 'y' or answer.lower() == 'yes':
			return True
		elif answer.lower() == 'n' or answer.lower() == 'no':
			return False
		elif answer == '':
			return True if self.default else False
		else:
			return self.ask()

class Open:
	def __init__(self, message):
		self.message = message

	def ask(self):
		return input(self.message + ' ').strip()
