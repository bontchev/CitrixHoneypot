
from twisted.python.logfile import DailyLogFile


class CitrixDailyLogFile(DailyLogFile):
    """
    Overload original Twisted with improved date formatting
    """

    def suffix(self, tupledate):
        """
        Return the suffix given a (year, month, day) tuple or unixtime
        """
        try:
            return "{:02d}-{:02d}-{:02d}".format(tupledate[0], tupledate[1], tupledate[2])
        except Exception:
            # try taking a float unixtime
            return '_'.join(map(str, self.toDate(tupledate)))

