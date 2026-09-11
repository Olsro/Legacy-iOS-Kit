"""Summarize restore phases without exposing noisy transport progress as totals."""
import re
import time


class RestoreProgress:
    PHASES = (
        ('Sending iBSS (', 'Sending the temporary USB bootloader'),
        ('Sending iBEC (', 'Sending the temporary restore bootloader'),
        ('Extracting filesystem from IPSW', 'Preparing the signed 8.4.1 system image on this computer'),
        ('Sending RestoreRamDisk (', 'Sending the RAM rescue'),
        ('Sending RestoreKernelCache (', 'Sending the RAM rescue kernel'),
        ('Waiting for device...', 'Waiting for the RAM rescue to connect'),
        ('Connected to com.apple.mobile.restored', 'RAM rescue connected'),
        ('Creating partition map', 'Preparing storage for the signed base'),
        ('Sending filesystem now', 'Sending the temporary iOS 8.4.1 system'),
        ('Verifying restore (', 'Verifying the restored iOS 8.4.1 system'),
        ('Flashing firmware (', 'Writing the signed boot firmware'),
        ('Updating baseband (', 'Updating the cellular modem'),
        ('Creating system key bag', 'Preparing device encryption metadata'),
        ('DONE', 'Restore tool finished; checking the RAM handoff'),
    )

    def __init__(self, emit, clock=time.monotonic):
        self.emit,self.clock=emit,clock
        self.pending='';self.phase=None;self.bucket=-1;self.percent_active=False
        self.last_update=self.last_notice=clock()

    def feed(self, text):
        lines=re.split(r'[\r\n]',self.pending+text)
        self.pending=lines.pop()[-8192:]
        for line in lines:
            for prefix, description in self.PHASES:
                if line.startswith(prefix):
                    if description != self.phase:
                        self.phase=description;self.bucket=-1;self.emit(description+'.')
                    self.percent_active=prefix.startswith(('Sending','Verifying','Flashing','Extracting filesystem'))
                    self.last_update=self.clock()
                    break
            else:
                if line.startswith(('Sending','Extracting')):self.percent_active=False
                match=re.fullmatch(r'\[[= ]+\]\s+(\d+(?:\.\d+)?)%',line.strip())
                if match and self.phase and self.percent_active:
                    percent=float(match[1]);bucket=int(percent)//10
                    self.last_update=self.clock()
                    if 0 <= percent <= 100 and bucket>self.bucket:
                        self.bucket=bucket
                        self.emit(self.phase+': '+str(int(percent))+'% (this step).')

    def tick(self):
        now=self.clock()
        if now-self.last_update>=45 and now-self.last_notice>=45:
            self.emit('Waiting for the next restore status ('+str(int(now-self.last_update))+
                      ' s without a new update). The phone display alone does not confirm progress. Keep the cable connected.')
            self.last_notice=now


# Preparation work runs on the calling thread; only the terminal refresh is in
# a background thread. No firmware/device operation is parallelized here.
import contextvars
from contextlib import contextmanager
import shutil
import sys
import threading

_display = contextvars.ContextVar('olsn0w_progress', default=None)


class LiveProgress:
    def __init__(self, emit=print, stream=None, clock=time.monotonic, refresh=.25):
        self.stream=stream or sys.stdout
        self.emit=emit;self.clock=clock;self.refresh=refresh
        self.interactive=emit is print and self.stream.isatty()
        self.lock=threading.RLock();self.stop=threading.Event()
        self.phase_name='';self.stack=[];self.last_log=0;self.width=0

    def __enter__(self):
        self.token=_display.set(self)
        self.thread=threading.Thread(target=self._refresh,daemon=True)
        self.thread.start()
        return self

    def __exit__(self,*error):
        self.stop.set();self.thread.join()
        with self.lock:
            if self.width:self.stream.write('\n');self.stream.flush();self.width=0
        _display.reset(self.token)

    def phase(self, number, label):
        with self.lock:
            self.phase_name='Preparation '+str(number)+'/5'
        self.message(self.phase_name+': '+label)

    def message(self, text):
        with self.lock:
            if self.width:
                self.stream.write('\r'+' '*self.width+'\r');self.width=0
            if self.emit is print:print(text,file=self.stream,flush=True)
            else:self.emit(text)

    def _refresh(self):
        while not self.stop.wait(self.refresh):self.render()

    def render(self, force=False, final=False):
        with self.lock:
            if not self.stack:return
            item=self.stack[-1];elapsed=max(0,self.clock()-item['start'])
            done,total=item['done'],item['total']
            prefix=(self.phase_name+' | ') if self.phase_name else ''
            if item['state']=='failed':value='failed'
            elif item['state']=='done':value='100%' if total else 'done'
            elif total:
                # The operation must return successfully before showing 100%.
                value=str(min(99,int(100*done/total)))+'%'
            else:value='working'
            text=prefix+item['label']+': '+value
            if total is not None or done:
                text+=' | '+format_bytes(done)
                if total:text+='/'+format_bytes(total)
                if elapsed>=1 and done:text+=' | '+format_bytes(done/elapsed)+'/s'
            text+=' | '+str(int(elapsed))+' s'
            if self.interactive:
                columns=shutil.get_terminal_size((100,24)).columns
                text=text[:max(1,columns-1)]
                self.stream.write('\r'+text+' '*max(0,min(self.width,columns-1)-len(text)))
                self.width=len(text)
                if final:self.stream.write('\n');self.width=0
                self.stream.flush()
            elif force or self.clock()-self.last_log>=15:
                if self.emit is print:print(text,file=self.stream,flush=True)
                else:self.emit(text)
                self.last_log=self.clock()


def format_bytes(value):
    for unit in ('B','KiB','MiB','GiB'):
        if value<1024 or unit=='GiB':return ('%.1f'%value)+' '+unit
        value/=1024


@contextmanager
def activity(label,total=None):
    """Report measured bytes, or elapsed activity when the total is unknown."""
    display=_display.get()
    if display is None:
        # Standalone downloads also get progress; other helpers stay quiet
        # unless explicitly run under a display.
        yield lambda done,total=None:None
        return
    item=dict(label=label,total=total,done=0,start=display.clock(),state='working')
    with display.lock:display.stack.append(item)
    def update(done,total=None):
        with display.lock:
            item['done']=max(0,done)
            if total is not None:item['total']=total if total>0 else None
    try:
        yield update
    except BaseException:
        with display.lock:item['state']='failed'
        display.render(force=True,final=True)
        raise
    else:
        with display.lock:
            item['state']='done'
            if item['total']:item['done']=item['total']
        # Small operations are common when assembling a filesystem. Avoid a
        # line for each file while still reporting long operations and errors.
        if display.clock()-item['start']>=1:display.render(force=True,final=True)
    finally:
        with display.lock:display.stack.remove(item)


@contextmanager
def display_if_needed():
    if _display.get() is not None:yield _display.get()
    else:
        with LiveProgress() as display:yield display


def copy_stream(source,destination,total,label):
    with activity(label,total) as update:
        done=0
        while True:
            block=source.read(1024**2)
            if not block:break
            destination.write(block);done+=len(block);update(done)


def message(text):
    display=_display.get()
    if display is None:print(text,flush=True)
    else:display.message(text)
