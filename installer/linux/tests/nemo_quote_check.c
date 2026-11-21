/* Run (Debian/Ubuntu): apt-get install gcc libglib2.0-dev pkg-config
   gcc -o nemo_quote_check nemo_quote_check.c $(pkg-config --cflags --libs glib-2.0) && ./nemo_quote_check
   3.1.0 #9-B: result recorded in docs/05 (GLib 2.84.4: 12/12 names one argument, nothing run). */
/* Nemo 9-B check: builds the Exec line the way nemo-action.c does for Quote=double
   (insert_quote + eel_str_escape_double_quoted_content, copied from linuxmint/nemo master)
   and splits it with GLib's g_shell_parse_argv, which g_spawn_command_line_async uses. */
#include <glib.h>
#include <string.h>
#include <stdio.h>

static char *esc(const char *s) {
    GString *g = g_string_new(NULL);
    for (const char *p = s; *p; p++) {
        if (*p == '"' || *p == '\\') g_string_append_c(g, '\\');
        g_string_append_c(g, *p);
    }
    return g_string_free(g, FALSE);
}

int main(void) {
    const char *names[] = {
        "/home/u/a b.txt",
        "/home/u/q\"uote.txt",
        "/home/u/$(touch /tmp/pwned).txt",
        "/home/u/`touch /tmp/pwned2`.txt",
        "/home/u/back\\slash\\\".txt",
        "/home/u/semi;colon&amp|pipe>x.txt",
        "/home/u/new\nline.txt",
        "/home/u/'single'.txt",
        "/home/u/#hash.txt",
        "/home/u/trailing\\",
        "/home/u/$HOME ${IFS}.txt",
        "/home/u/--open",
        NULL };
    int fails = 0;
    for (int i = 0; names[i]; i++) {
        char *e = esc(names[i]);
        char *line = g_strdup_printf("\"/usr/bin/shield-gui\" --open \"%s\"", e);
        int argc; char **argv; GError *err = NULL;
        if (!g_shell_parse_argv(line, &argc, &argv, &err)) {
            printf("PARSE FAIL %s: %s\n", names[i], err->message);
            fails++;
            continue;
        }
        int ok = argc == 3 && strcmp(argv[0], "/usr/bin/shield-gui") == 0 && strcmp(argv[1], "--open") == 0 &&
                 strcmp(argv[2], names[i]) == 0;
        char *shown = g_strescape(argc > 2 ? argv[2] : "", NULL);
        printf("%s argc=%d [%s]\n", ok ? "ok  " : "FAIL", argc, shown);
        fails += !ok;
        g_free(shown); g_strfreev(argv); g_free(line); g_free(e);
    }
    printf("pwned files: %s %s\n", g_file_test("/tmp/pwned", G_FILE_TEST_EXISTS) ? "YES" : "no",
           g_file_test("/tmp/pwned2", G_FILE_TEST_EXISTS) ? "YES" : "no");
    printf("failures=%d\n", fails);
    return fails != 0;
}
