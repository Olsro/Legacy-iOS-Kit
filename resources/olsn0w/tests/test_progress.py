from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from progress import RestoreProgress
from restore import copy_image


class ProgressMessages(unittest.TestCase):
    def test_split_log_records_reset_percentage_between_steps(self):
        messages=[];p=RestoreProgress(messages.append)
        p.feed('Sending filesystem n');p.feed('ow...\n[==== ] 100.0%\rVerifying restore (14)\n[= ] 2.0%\r')
        self.assertTrue(any('system: 100%' in m for m in messages))
        self.assertTrue(any('Verifying' in m and '2%' in m for m in messages))
        count=len(messages)
        p.feed('Sending KernelCache now...\n[== ] 90.0%\r')
        self.assertEqual(len(messages),count)
        p.feed('DONE\n')
        self.assertIn('checking the RAM handoff',messages[-1])

    def test_silent_wait_does_not_claim_progress(self):
        now=[0];messages=[];p=RestoreProgress(messages.append,lambda:now[0])
        now[0]=46;p.tick();p.tick()
        self.assertEqual(len(messages),1)
        self.assertIn('without a new update',messages[0])

    def test_sparse_copy_reports_transferred_bytes_not_last_disk_offset(self):
        with tempfile.TemporaryDirectory() as tmp:
            file=Path(tmp)/'data.hfs'
            with file.open('wb') as stream:stream.truncate(1001*4096)
            ram=Mock();messages=[]
            with patch('restore.allocated_ranges',return_value=[(0,1),(1000,1)]):
                copy_image(ram,file,'/dev/rdisk0s1s2',sparse=True,progress=messages.append,label='Initial data')
            self.assertEqual(ram.write.call_count,2)
            self.assertIn('100%',messages[-1])
            self.assertIn('0.0/0.0 MiB',messages[-1])
            self.assertNotIn('3.9',messages[-1])


import io
from progress import LiveProgress, activity
from firmware import content_length, fetch


class LiveMessages(unittest.TestCase):
    def test_unknown_duration_is_not_a_fabricated_percentage(self):
        stream=io.StringIO();now=[0]
        with LiveProgress(stream=stream,clock=lambda:now[0],refresh=100) as display:
            display.phase(2,'Preparing system')
            with activity('Preparing filesystem'):
                now[0]=20;display.render(force=True)
        self.assertIn('working',stream.getvalue());self.assertIn('20 s',stream.getvalue())
        self.assertNotIn('%',stream.getvalue())

    def test_no_100_percent_before_success_or_after_failure(self):
        stream=io.StringIO();now=[0]
        with LiveProgress(stream=stream,clock=lambda:now[0],refresh=100) as display:
            with self.assertRaises(RuntimeError):
                with activity('Copying',100) as update:
                    update(100);now[0]=2;display.render(force=True)
                    raise RuntimeError('write failed')
        self.assertIn('99%',stream.getvalue());self.assertIn('failed',stream.getvalue())
        self.assertNotIn('100%',stream.getvalue())

    def test_nested_progress_resumes_parent_and_tty_overwrites_line(self):
        stream=io.StringIO();stream.isatty=lambda:True;now=[0]
        with LiveProgress(stream=stream,clock=lambda:now[0],refresh=100) as display:
            with activity('Parent'):
                with activity('Download',100) as update:
                    update(50);now[0]=1;display.render()
                    update(100);now[0]=2
                display.render()
        output=stream.getvalue()
        self.assertIn('\r',output);self.assertIn('50%',output);self.assertIn('100%',output)
        self.assertIn('Parent: working',output)

    def test_log_output_throttled_and_has_no_terminal_escapes(self):
        stream=io.StringIO();now=[0]
        with LiveProgress(stream=stream,clock=lambda:now[0],refresh=100) as display:
            with activity('Download',1000) as update:
                for i in range(1,31):
                    now[0]=i;update(i);display.render()
        output=stream.getvalue()
        self.assertLessEqual(len(output.splitlines()),3);self.assertNotIn('\r',output)

    def test_redirect_and_unknown_download_length(self):
        self.assertEqual(content_length('HTTP/1.1 302 Found\r\nContent-Length: 12\r\n\r\nHTTP/2 200\r\ncontent-length: 999\r\n\r\n'),999)
        self.assertIsNone(content_length('HTTP/1.1 302 Found\r\nContent-Length: 12\r\n\r\n'))
        self.assertIsNone(content_length('HTTP/2 200\r\nTransfer-Encoding: chunked\r\n\r\n'))

    def test_failed_download_never_replaces_destination(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'test.ipsw';path.write_bytes(b'previous')
            process=Mock();process.wait.return_value=22;process.poll.return_value=22
            with patch('firmware.subprocess.Popen',return_value=process),patch('sys.stdout',io.StringIO()):
                with self.assertRaisesRegex(RuntimeError,'Download failed'):fetch('https://example.invalid/firmware',path)
            self.assertEqual(path.read_bytes(),b'previous')

    def test_successful_download_publishes_only_expected_size(self):
        for expected in (3,4):
            with self.subTest(expected=expected),tempfile.TemporaryDirectory() as folder:
                path=Path(folder)/'test.ipsw';process=Mock();process.wait.return_value=0;process.poll.return_value=0
                def launch(argv,**kwargs):
                    Path(argv[argv.index('--output')+1]).write_bytes(b'new')
                    return process
                with patch('firmware.subprocess.Popen',side_effect=launch),patch('sys.stdout',io.StringIO()):
                    if expected==3:
                        fetch('https://example.invalid/firmware',path,total=expected)
                        self.assertEqual(path.read_bytes(),b'new')
                    else:
                        with self.assertRaisesRegex(RuntimeError,'size differs'):fetch('https://example.invalid/firmware',path,total=expected)
                        self.assertFalse(path.exists())
