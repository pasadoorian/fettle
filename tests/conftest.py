import os

# Belt-and-suspenders: never let a test trigger the sudo re-exec path.
os.environ["FETTLE_TEST"] = "1"
