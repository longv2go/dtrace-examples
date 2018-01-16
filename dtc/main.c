//
//  main.c
//  dtc
//
//  Created by albert on 2018/1/15.
//  Copyright © 2018年 ant. All rights reserved.
//

#include <stdio.h>
#include <dtrace.h>

/*ARGSUSED*/
static int
chewrec(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
    dtrace_actkind_t act;
    uintptr_t addr;
    
    if (rec == NULL) {
        /*
         * We have processed the final record; output the newline if
         * we're not in quiet mode.
         */

        
        return (DTRACE_CONSUME_NEXT);
    }
    
    act = rec->dtrd_action;
    addr = (uintptr_t)data->dtpda_data;
    
    if (act == DTRACEACT_EXIT) {
        return (DTRACE_CONSUME_NEXT);
    }
    
    return (DTRACE_CONSUME_THIS);
}

/*ARGSUSED*/
static int
chew(const dtrace_probedata_t *data, void *arg)
{
//    dtrace_probedesc_t *pd = data->dtpda_pdesc;
//    processorid_t cpu = data->dtpda_cpu;
//    static int heading;
//
//
//    if (heading == 0) {
//        if (!g_flowindent) {
//            if (!g_quiet) {
//                oprintf("%3s %6s %32s\n",
//                        "CPU", "ID", "FUNCTION:NAME");
//            }
//        } else {
//            oprintf("%3s %-41s\n", "CPU", "FUNCTION");
//        }
//        heading = 1;
//    }
//
//    if (!g_flowindent) {
//        if (!g_quiet) {
//            char name[DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 2];
//
//            (void) snprintf(name, sizeof (name), "%s:%s",
//                            pd->dtpd_func, pd->dtpd_name);
//
//            oprintf("%3d %6d %32s ", cpu, pd->dtpd_id, name);
//        }
//    } else {
//        int indent = data->dtpda_indent;
//        char *name;
//        size_t len;
//
//        if (data->dtpda_flow == DTRACEFLOW_NONE) {
//            len = indent + DTRACE_FUNCNAMELEN + DTRACE_NAMELEN + 5;
//            name = alloca(len);
//            (void) snprintf(name, len, "%*s%s%s:%s", indent, "",
//                            data->dtpda_prefix, pd->dtpd_func,
//                            pd->dtpd_name);
//        } else {
//            len = indent + DTRACE_FUNCNAMELEN + 5;
//            name = alloca(len);
//            (void) snprintf(name, len, "%*s%s%s", indent, "",
//                            data->dtpda_prefix, pd->dtpd_func);
//        }
//
//        oprintf("%3d %-41s ", cpu, name);
//    }
//
    return (DTRACE_CONSUME_THIS);
}

static int
chewrec2(const dtrace_probedata_t *data, const dtrace_recdesc_t *rec, void *arg)
{
    if (rec == NULL)
        return (DTRACE_CONSUME_NEXT);
    
    switch (rec->dtrd_action) {
        case DTRACEACT_DIFEXPR:
            (void) printf("%s\n", data->dtpda_data);
            return (DTRACE_CONSUME_NEXT);
        case DTRACEACT_EXIT:
//            g_exit = 1;
            return (DTRACE_CONSUME_NEXT);
        default:
            (void) printf("%d\n", rec->dtrd_action);
            return (DTRACE_CONSUME_NEXT);
    }
    
    return (DTRACE_CONSUME_THIS);
}

int main(int argc, const char * argv[]) {
    int err;
    dtrace_hdl_t *dh;
    
    dh = dtrace_open(DTRACE_VERSION, 0, &err);
    
    if (dh == NULL) {
        printf("Can not open dtrace: %s\n", dtrace_errmsg(NULL, err));
        return -1;
    }
    
    FILE *pfile;
    dtrace_prog_t *prog;
    
    pfile = fopen(argv[1], "r");
    prog = dtrace_program_fcompile(dh, pfile, DTRACE_C_CPP, 0, NULL);
    
    if (prog == NULL) {
        printf("Compile %s failed\n", argv[1]);
        return -1;
    }
    
    fclose(pfile);
    
    dtrace_proginfo_t info;
    dtrace_program_exec(dh, prog, &info);
    // check
    
    dtrace_go(dh);
    // check
    
    int done = 0;
    while(!done) {
        dtrace_sleep(dh);
        
        switch (dtrace_work(dh, stdout, NULL, chewrec2, NULL)) {
            case DTRACE_WORKSTATUS_DONE:
                done = 1;
                break;
            case DTRACE_WORKSTATUS_OKAY:
                break;
            default:
                done = 1;
        }
    }
    
    printf("-------\n");
    
    
    return 0;
}
