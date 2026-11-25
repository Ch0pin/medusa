"""Optional presentation-only aggregation; source log bytes are never edited."""
import time


_COUNTERS = {'timestamp', 'first_timestamp', 'last_timestamp', 'repeat_count',
             'event_sequence', 'last_event_sequence'}


def same_console_event(first, second):
    return (first.get('type') == second.get('type') == 'console'
            and {k: v for k, v in first.items() if k not in _COUNTERS}
            == {k: v for k, v in second.items() if k not in _COUNTERS})


def combine_events(first, second):
    result = dict(first)
    result.update(repeat_count=first.get('repeat_count', 1) + second.get('repeat_count', 1),
                  first_timestamp=first.get('first_timestamp', first.get('timestamp')),
                  last_timestamp=second.get('last_timestamp', second.get('timestamp')),
                  timestamp=second.get('timestamp'),
                  last_event_sequence=second.get('last_event_sequence', second.get('event_sequence')))
    return result


def compact_events(events):
    result = []
    for event in events:
        if result and same_console_event(result[-1], event):
            result[-1] = combine_events(result[-1], event)
        else:
            result.append(dict(event))
    return result


def compact_lines(lines, start_line=0):
    """Ranges are one-based physical source lines; cursor offsets stay raw."""
    output, groups = [], []
    index = 0
    while index < len(lines):
        end = index + 1
        if lines[index].strip():
            while end < len(lines) and lines[end] == lines[index]:
                end += 1
        count = end - index
        output.append(lines[index])
        if count > 1:
            first, last = start_line + index + 1, start_line + end
            if not output[-1].endswith('\n'):
                output.append('\n')
            output.append(f'[medusa-mcp] repeated {count} times across source lines {first}-{last} ({count - 1} additional)\n')
            groups.append({'count': count, 'first_line': first, 'last_line': last})
        index = end
    return ''.join(output), groups


class ConsoleAggregator:
    """Collapse exact adjacent lines, with periodic and final count summaries."""
    def __init__(self, write, interval=1.0):
        self.write = write
        self.interval = interval
        self.buffer = ''
        self.context = None
        self.line = None
        self.count = self.reported = 0
        self.last_summary = time.monotonic()

    def _summary(self):
        if self.count > self.reported:
            self.write(f'[medusa-mcp] repeated {self.count} times total ({self.count - self.reported} additional)\n')
            self.reported = self.count
            self.last_summary = time.monotonic()

    def _line(self, line):
        if line.strip() and line == self.line:
            self.count += 1
            if time.monotonic() - self.last_summary >= self.interval:
                self._summary()
            return
        self._summary()
        self.write(line)
        self.line, self.count, self.reported = line, 1, 1
        self.last_summary = time.monotonic()

    def feed(self, data, context):
        if context != self.context:
            self.finish()
            self.context = context
        self.buffer += data
        while '\n' in self.buffer:
            line, self.buffer = self.buffer.split('\n', 1)
            self._line(line + '\n')
        if len(self.buffer) >= 65536:
            self.finish()  # Bound the extra display buffer without truncation.

    def finish(self):
        self._summary()
        if self.buffer:
            self.write(self.buffer)
        self.buffer, self.line = '', None
        self.count = self.reported = 0
