import time

from avocado.utils import process

ubbdd_stopping = False
proc = None

def start_ubbdd(ubbdd_bin, timeout):
    while (!ubbdd_stopping) {
        proc = process.get_sub_process_klass(ubbdd_bin)(ubbdd_bin)
        pid = proc.start()
        self.log.info("ubbdd started: pid: %s, %s", pid, proc)
        time.sleep(timeout)
        proc.stop()
        proc.wait()
    }

def stop_ubbdd():
    ubbdd_stopping = True
    if (proc):
        proc.stop()
        proc.wait()
    print("ubbdd stopped")
