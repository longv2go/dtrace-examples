#include <dtrace.h>
#include <stdlib.h>
#include <string.h>

static const char *g_script =
"syscall::open*:entry { printf(\"%s %s\",execname,copyinstr(arg0)); }";

static dtrace_hdl_t *g_dtp;

/*PRINTFLIKE1*/
static void
die(const char *fmt, ...)
{
    va_list ap;
    
    va_start(ap, fmt);
    (void) vfprintf(stderr, fmt, ap);
    va_end(ap);
    
    exit(1);
}

/*PRINTFLIKE1*/
static void
ddie(const char *fmt, ...)
{
    va_list ap;
    
    va_start(ap, fmt);
    (void) vfprintf(stderr, fmt, ap);
    if (fmt[strlen(fmt) - 1] != '\n') {
        (void) fprintf(stderr, ": %s\n",
                       dtrace_errmsg(g_dtp, dtrace_errno(g_dtp)));
    }
    va_end(ap);
    
    exit(1);
}

static int g_exit;

static int
chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
    if (rec == NULL)
        return (DTRACE_CONSUME_NEXT);
    
    switch (rec->dtrd_action) {
        case DTRACEACT_DIFEXPR:
            (void) printf("%s\n", data->dtpda_data);
            return (DTRACE_CONSUME_NEXT);
        case DTRACEACT_EXIT:
            g_exit = 1;
            return (DTRACE_CONSUME_NEXT);
        default:
            (void) printf("%d\n", rec->dtrd_action);
            return (DTRACE_CONSUME_NEXT);
    }
    
    return (DTRACE_CONSUME_THIS);
}

int
main(int argc, char **argv)
{
    int err;
    
    if ((g_dtp = dtrace_open(DTRACE_VERSION, 0, &err)) == NULL) {
        die("failed to initialize: %s\n",
            dtrace_errmsg(NULL, err));
    }
    
    if (dtrace_setopt(g_dtp, "bufsize", "1k") == -1)
        ddie("failed to set 'bufsize'");
    
    dtrace_prog_t *prog;
    dtrace_proginfo_t info;
    
    if ((prog = dtrace_program_strcompile(g_dtp, g_script,
                                          DTRACE_PROBESPEC_NAME, 0, 0, NULL)) == NULL) {
        die("failed to compile\n");
    }
    
    if (dtrace_program_exec(g_dtp, prog, &info) == -1)
        die("failed to enable probes\n");
    
    if (dtrace_go(g_dtp) != 0)
        ddie("failed to start");
    
    int done = 0;
    
    do {
        if (!g_exit && !done)
            dtrace_sleep(g_dtp);
        
        if (g_exit || done) {
            done = 1;
            if (dtrace_stop(g_dtp) == -1)
                ddie("failed to stop");
        }
        
        switch (dtrace_work(g_dtp, stdout, NULL, chewrec, NULL)) {
            case DTRACE_WORKSTATUS_DONE:
                done = 1;
                break;
            case DTRACE_WORKSTATUS_OKAY:
                break;
            default:
                die("processing aborted");
        }
    } while (!done);
    
    dtrace_close(g_dtp);
    
    return (0);
}
