try:
    import sys    
    if sys.hexversion < 0x3050000:
        raise ImportError("Python version must be >= 3.5")
    import logging.config
    from pathlib import Path
    import yaml
    import re
    import os
    import pty
    import traceback
    from random import randint
    from obd_message import ObdMessage, ECU_ADDR_E, ELM_R_OK
    import can #pip install python-can
    import threading
    import logging
    import time
    from cmd import Cmd
    import rlcompleter
    import os.path
    try:
        import readline
    except ImportError:
        readline = None
except ImportError as detail:
    print("ELM327 OBDII adapter emulator error:\n " + str(detail))
    sys.exit(1)


def setup_logging(
        default_path=Path(__file__).stem + '.yaml',
        default_level=logging.INFO,
        env_key=os.path.basename(Path(__file__).stem).upper() + '_LOG_CFG'):
    path = default_path
    value = os.getenv(env_key, None)
    if value:
        path = value
    if os.path.exists(path):
        with open(path, 'rt') as f:
            config = yaml.safe_load(f.read())
        logging.config.dictConfig(config)
    else:
        logging.basicConfig(level=default_level)

class THREAD:
    STOPPED = 0
    STARTING = 1
    ACTIVE = 2
    PAUSED = 3

class ELM:
    ELM_VALID_CHARS = r"[a-zA-Z0-9 \n\r]*"

    # Other AT commands (still to be implemented...)
    ELM_DEFAULTS           = r"ATD$"
    ELM_SET_PROTO          = r"ATSPA?[0-9A-C]$"
    ELM_ERASE_PROTO        = r"ATSP00$"

    def Sequence(self, pid, base, max, factor, n_bytes):
        c = self.counters[pid]
        # compute the new value [= factor * ( counter % (max * 2) )]
        p = int (factor * abs( max - ( c + max ) % (max * 2) ) ) + base
        # get its hex string
        s = ("%.X" % p).zfill(n_bytes * 2)
        # space the string into chunks of two bytes
        return (" ".join(s[i:i + 2] for i in range(0, len(s), 2)))

    def reset(self, sleep):
        """ returns all settings to their defaults """
        logging.debug("Resetting counters and sleeping for %s seconds", sleep)
        time.sleep(sleep)
        for i in [k for k in self.counters if k.startswith('cmd_')]:
            del(self.counters[i])
        self.counters['ELM_PIDS_A'] = 0
        self.counters['ELM_MIDS_A'] = 0
        self.counters["cmd_header"] = ECU_ADDR_E

    def set_defaults(self):
        self.delay = 0
        self.max_req_timeout = 1440
        self.answer = {}
        self.counters = {}

    def setSortedOBDMsg(self):
        self.sortedOBDMsg = {
            **self.ObdMessage['default'], # highest priority
            **self.ObdMessage['AT'],
            }
        self.sortedOBDMsg = sorted(self.sortedOBDMsg.items(), key = lambda x: x[1]['Priority'] if 'Priority' in x[1] else 10 )

    def __init__(self, serial_port):
        self.ObdMessage = ObdMessage
        self.set_defaults()
        self.setSortedOBDMsg()
        self.serial_port = serial_port
        self.reset(0)
        self.tmp_arbitration_id = False

    def __enter__(self):
        # make a new pty
        self.master_fd, self.slave_fd = pty.openpty()
        self.slave_name = os.ttyname(self.slave_fd)

        # start the read thread
        self.threadState = THREAD.STARTING
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()

        return self.slave_name

    def __exit__(self, exc_type, exc_value, traceback):
        self.threadState = THREAD.STOPPED
        time.sleep(0.1)
        if os.name == 'nt':
            self.master_fd.close()
        else:
            os.close(self.slave_fd)
            os.close(self.master_fd)
        return False  # don't suppress any exceptions

    def run(self): # daemon thread #CHECKED
        setup_logging()
        self.logger = logging.getLogger()
        logging.info('\n\nELM327 OBD-II adapter emulator started\n')
        """ the ELM's main IO loop """
        
        self.threadState = THREAD.ACTIVE
        while self.threadState != THREAD.STOPPED:

            if self.threadState == THREAD.PAUSED:
                time.sleep(0.1)
                continue

            # get the latest command
            self.cmd = self.read()
            if self.threadState == THREAD.STOPPED:
                return

            # process 'fast' option
            if re.match('^ *$', self.cmd) and "last_cmd" in self.counters:
                self.cmd = self.counters["last_cmd"]
                logging.debug("repeating previous command: %s", repr(self.cmd))
            else:
                self.counters["last_cmd"] = self.cmd
                logging.debug("Received %s", repr(self.cmd))

            # if it didn't contain any egregious errors, handle it
            if self.validate(self.cmd):
                try:
                    resp = self.handle(self.cmd)
                except Exception as e:
                    logging.critical("Error while processing %s:\n%s\n%s", repr(self.cmd), e, traceback.format_exc())
                    continue
                self.write(resp)
            else:
                logging.warning("Invalid request: %s", repr(self.cmd))

    def read(self):#CHECKED
        '''
        Reads the next newline delimited command from the port filters 
        @returns: normalized string command
        '''
        buffer = ""
        first = True
        req_timeout = self.max_req_timeout
        try:
            req_timeout = float(self.counters['req_timeout'])
        except Exception as e:
            if 'req_timeout' in self.counters:
                logging.error("Improper configuration of\n\"self.counters['req_timeout']\": '%s' (%s). Resetting it to %s", self.counters['req_timeout'], e, self.max_req_timeout)
            self.counters['req_timeout'] = req_timeout
        while True:
            prev_time = time.time()
            try:
                c = os.read(self.master_fd, 1).decode()
            except UnicodeDecodeError as e:
                logging.warning("Invalid character received: %s", e)
                return('')
            except OSError:
                return('')
            if prev_time + req_timeout < time.time() and first == False:
                buffer = ""
                logging.debug("'req_timeout' timeout while reading data: %s", c)
            if c == '\r':
                break
            if c == '\n':
                continue  # ignore newlines
            first = False
            buffer += c

        return buffer

    def write(self, resp):#CHECKED
        '''
        Writes a response to the port.
        @param resp (string): string to send to port.
        '''
        n = "\r\n" if 'cmd_linefeeds' in self.counters and self.counters[
            'cmd_linefeeds'] == 1 else "\r"
        resp += n + ">"
        nospaces = 1 if 'cmd_spaces' in self.counters and self.counters[
            'cmd_spaces'] == 0 else 0

        j=0
        for i in re.split(r'\0([^\0]+)\0', resp):
            if j % 2:
                msg = i.strip()
                try:
                    evalmsg = eval(msg)
                    if nospaces:
                        evalmsg = re.sub(r'[ \t]+', '', evalmsg)
                    logging.debug("Evaluated command: %s", msg)
                    if evalmsg != None:
                        if os.name == 'nt':
                            self.master_fd.write(evalmsg.encode())
                        else:
                            os.write(self.master_fd, evalmsg.encode())
                        logging.debug("Written evaluated command: %s", repr(evalmsg))
                except Exception:
                    try:
                        logging.debug("Executing command: %s", msg)
                        if msg:
                            exec(msg, globals())
                    except Exception as e:
                        logging.error("Cannot execute '%s': %s", i, e)
            else:
                logging.debug("Write: %s", repr(i))
                if nospaces:
                    i = re.sub(r'[ \t]+', '', i)
                if os.name == 'nt':
                    self.master_fd.write(i.encode())
                else:
                    os.write(self.master_fd, i.encode())
            j += 1

    def validate(self, cmd):
        if not re.match(self.ELM_VALID_CHARS, cmd):
            return False
        return True#CHEKCED

    def saveArbID(self, cmd):
        '''
        Stores the Arbitration ID from the CAN packet when receiving the first part of the message.
        @param cmd (string): message received on virtual serial port.
        '''
        self.tmp_arbitration_id = cmd.split('ATSH')[1]
        return

    def sendToICSim(self, cmd):
        '''
        Send CAN packet to ICSim when receiving the data of the message.
        @param cmd (string): message received on virtual serial port.
        '''
        logging.info("Olrait!!" + cmd)
        if self.tmp_arbitration_id != False:
            arb_id = self.tmp_arbitration_id
            self.tmp_arbitration_id = False
        else:
            logging.error("NO ARB ID PREVIOUSLY STORED...")
            return
        bus = can.interface.Bus(channel='vcan0', bustype='socketcan')
        data = bytearray.fromhex(cmd)
        logging.info("This is the data I want to send: " + str(arb_id) + "#" + str(data))
        msg = can.Message(arbitration_id=int(arb_id, 16), data=data, is_extended_id=False)
        bus.send(msg)
        bus.shutdown()
        return

    def handle(self, cmd):#CHECKED.
        '''
        Handles received commands and, if they are commands for ICSim, sends them to ICSim.
        @param cmd (string): message received on virtual serial port.
        '''
        '''
        EXTRACTED FROM ELM327_RELAY.RB...
        def connect_to_device()
              [...]
              resp = send_cmd("ATZ")  # Turn off ECHO
              if resp =~ /ELM327/
                send_cmd("ATE0")  # Turn off ECHO
                send_cmd("ATL0")  # Disble linefeeds
                @device_name = send_cmd("ATI")
                send_cmd("ATH1") # Show Headers
                
            [...]
        def cansend(id, data)
              [...]
              resp = send_cmd("ATSH#{id}")
              if resp == "OK"
                send_cmd("ATR0") # Disable response checks
                send_cmd("ATCAF0") # Turn off ISO-TP formatting
              [...]
              send_cmd(data)
        '''
        #########################
        '''
        management_headers = ["ATZ", "ATE0", "ATL0", "ATI", "ATH1", "ATR0", "ATCAF0", "ATCRA"]
        tosend = True
        for i in management_headers:
            if i in cmd:
                tosend = False
        if tosend:
            if "ATSH" in cmd:
                logging.info("Found packet to ICSim. Specifying Arbitration ID: " + cmd)
                self.saveArbID(cmd)
            else:
                logging.info("Found complete packet to ICSim. Sending to ICSim..." + cmd)
                self.sendToICSim(cmd)
        '''
        logging.info(cmd)
        print(cmd)
        for i in self.sortedOBDMsg:
            key = i[0]
            val = i[1]

            if 'Request' in val and re.match(val['Request'], cmd):
                if 'Header' in val and val['Header'] != self.counters["cmd_header"]:
                    continue
                if key:
                    pid = key
                else:
                    pid = 'UNKNOWN'
                if pid not in self.counters:
                    self.counters[pid] = 0
                self.counters[pid] += 1
                if 'Action' in val and val['Action'] == 'skip':
                    logging.info("Received %s. PID %s. Action=%s", cmd, pid, val['Action'])
                    continue
                if 'Descr' in val:
                    logging.debug("Description: %s, PID %s (%s)", val['Descr'], pid, cmd)
                else:
                    logging.error(
                        "Internal error - Missing description for %s, PID %s", cmd, pid)
                if pid in self.answer:
                    try:
                        return(self.answer[pid])
                    except Exception as e:
                        logging.error(
                        "Error while processing '%s' for PID %s (%s)", self.answer, pid, e)
                if 'Response' in val:
                    header = ''
                    if 'ResponseHeader' in val:
                        header = val['ResponseHeader'](
                            self, cmd, pid, val)
                    footer = ''
                    if 'ResponseFooter' in val:
                        footer = val['ResponseFooter'](
                            self, cmd, pid, val)
                    response=val['Response']
                    if isinstance(response, (list, tuple)):
                        response=response[randint(0, len(response)-1)]
                    return (header + response + footer)
        return ""

    def sanitize(self, cmd):
        cmd = cmd.replace(" ", "")
        cmd = cmd.upper()
        return cmd


class Interpreter(Cmd):
    __hiden_methods = ('do_EOF',)
    rlc = rlcompleter.Completer().complete
    histfile = os.path.expanduser('~/.ELM327_emulator_history')
    histfile_size = 1000

    def __init__(self, emulator):
        self.emulator = emulator
        self.prompt_active = True
        self.color_active = True
        Cmd.__init__(self)

    def preloop(self):
        if readline and os.path.exists(self.histfile):
            try:
                readline.read_history_file(self.histfile)
            except FileNotFoundError:
                pass

    def postloop(self):
        if readline:
            readline.set_history_length(self.histfile_size)
            readline.write_history_file(self.histfile)
        if self.color_active:
            sys.stdout.write("\033[00m")
            sys.stdout.flush()

#######Create some commands to enable debugging, exit etc.


if __name__ == '__main__':
    p_elm = None
    try:
        emulator = ELM('COM3')
        with emulator as pts_name:
            if pts_name == None:
                print("\nCannot start ELM327-emulator.")
                os._exit(1) # does not raise SystemExit
            while emulator.threadState == THREAD.STARTING:
                time.sleep(0.1)
            sys.stdout.flush()

            p_elm = Interpreter(emulator)
            p_elm.cmdloop('Welcome to the ELM327 OBDII adapter emulator.\nELM327-emulator is running on %s\n' % pts_name)
    except (KeyboardInterrupt, SystemExit):
        print("\nELM327-emulator ENDED")
        sys.exit(0)
    sys.exit(1)
