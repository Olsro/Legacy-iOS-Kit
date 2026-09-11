/* The pinned held untether emits this line after its final kernel write.
 * Parse the child's fresh output stream, including lines split across reads. */
struct patch_completion { unsigned int matched; int ready; };
static void patch_completion_feed(struct patch_completion *state,
                                  const char *bytes, unsigned long count) {
    static const char marker[] = "enable patched.\n";
    for (unsigned long i = 0; i < count; i++) {
        if (bytes[i] == marker[state->matched]) {
            if (++state->matched == sizeof(marker) - 1) {
                state->ready = 1;
                state->matched = 0;
            }
        } else {
            state->matched = bytes[i] == marker[0] ? 1 : 0;
        }
    }
}
