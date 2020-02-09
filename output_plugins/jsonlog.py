
import os
import json
import copy
import errno

import core.output

from core.config import CONFIG
from core.logfile import CitrixDailyLogFile

class Output(core.output.Output):

    def start(self):
        self.epoch_timestamp = CONFIG.getboolean('output_jsonlog', 'epoch_timestamp', fallback=False)
        fn = CONFIG.get('output_jsonlog', 'logfile')
        dirs = os.path.dirname(fn)
        base = os.path.basename(fn)
        if not os.path.exists(dirs) and os.sep in fn:
            try:
                os.makedirs(dirs)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise
        self.outfile = CitrixDailyLogFile(base, dirs, defaultMode=0o664)

    def stop(self):
        self.outfile.flush()

    def write(self, event):
        if not self.epoch_timestamp:
            # We need 'unixtime' value in some other plugins
            event_dump = copy.deepcopy(event)
            event_dump.pop('unixtime', None)
        else:
            event_dump = event
        json.dump(event_dump, self.outfile, separators=(',', ':'))
        self.outfile.write('\n')
        self.outfile.flush()
