//
//  main.c
//  dofc
//
//  Created by albert on 2018/1/16.
//  Copyright © 2018年 ant. All rights reserved.
//

#include <stdio.h>
#include <dtrace.h>

int main(int argc, const char * argv[]) {
    int err;
    dtrace_hdl_t *dh;
    
    dh = dtrace_open(DTRACE_VERSION, 0, &err);
    
    FILE *pfile;
    dtrace_prog_t *prog;
    
    if (!argv[1]) {
        printf("No input file\n");
        exit(1);
    }
    pfile = fopen(argv[1], "r");
    prog = dtrace_program_fcompile(dh, pfile, DTRACE_C_CPP, 0, NULL);
    
    void *dof = dtrace_dof_create(dh, prog, 0);
    if (dof && argv[2]) {
        dof_hdr_t *hdr = dof;
        uint64_t size = hdr->dofh_filesz;
        
        FILE *fp = fopen(argv[2], "w+");
        fwrite(dof, size, 1, fp);
        fclose(fp);
    }
    
    dt_node_printr();
    return 0;
}
