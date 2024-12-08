from datetime import datetime
from time import localtime, strftime

print(strftime("%Y-%m-%d %H:%M:%S %Z", localtime()))