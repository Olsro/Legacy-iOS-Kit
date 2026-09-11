"""Completion detection must survive pipe read boundaries and partial output."""
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(shutil.which('cc'), 'Native C compiler unavailable')
class PatchCompletion(unittest.TestCase):
    def test_split_and_incomplete_marker(self):
        source = r'''
#include "patch_completion.h"
#include <string.h>
int main(void) {
    const char *line = "kernel found\nenable patched.\n";
    unsigned long length = strlen(line);
    for (unsigned long split = 0; split < length; split++) {
        struct patch_completion state = {0};
        patch_completion_feed(&state, line, split);
        if (state.ready) return 1;
        patch_completion_feed(&state, line + split, length - split);
        if (!state.ready) return 2;
    }
    struct patch_completion state = {0};
    const char *failed = "enable patch failed\nenable patched.";
    patch_completion_feed(&state, failed, strlen(failed));
    if (state.ready) return 3;
    patch_completion_feed(&state, "\n", 1);
    if (!state.ready) return 4;
    struct patch_completion next_boot = {0};
    if (next_boot.ready) return 5;
    return 0;
}
'''
        with tempfile.TemporaryDirectory() as folder:
            folder = Path(folder)
            (folder/'test.c').write_text(source)
            subprocess.run(['cc', '-I'+str(ROOT/'native/bootstrap'),
                            str(folder/'test.c'), '-o', str(folder/'test')],
                           check=True, capture_output=True)
            subprocess.run([folder/'test'], check=True, capture_output=True)
