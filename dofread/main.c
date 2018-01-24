//
//  main.c
//  dofread
//
//  Created by albert on 2018/1/18.
//  Copyright © 2018年 ant. All rights reserved.
//

#include <stdio.h>
#include <dtrace.h>
#include <sys/stat.h>
#include <assert.h>
#include <getopt.h>
#include <mach-o/loader.h>

// relocation_info.r_length field has value 3 for 64-bit executables and value 2 for 32-bit executables
#if __LP64__
#define LC_SEGMENT_COMMAND        LC_SEGMENT_64
#define LC_ROUTINES_COMMAND       LC_ROUTINES_64
#define LC_SEGMENT_COMMAND_WRONG  LC_SEGMENT
#else
#define LC_SEGMENT_COMMAND        LC_SEGMENT
#define LC_ROUTINES_COMMAND        LC_ROUTINES
#define LC_SEGMENT_COMMAND_WRONG LC_SEGMENT_64
#endif

extern int errno;
static const char *optString = "mh?";

int g_opt_macho = 0;

static void
verror(const char *fmt, va_list ap)
{
//    int error = errno;
    (void) vfprintf(stderr, fmt, ap);
}

/*PRINTFLIKE1*/
static void
error(const char *fmt, ...)
{
    va_list ap;
    
    va_start(ap, fmt);
    verror(fmt, ap);
    va_end(ap);
}

char * type_to_string(int type) {
    static char *t2s[] = {
        "DOF_SECT_NONE", 
        "DOF_SECT_COMMENTS",
        "DOF_SECT_SOURCE",   
        "DOF_SECT_ECBDESC", 
        "DOF_SECT_PROBEDESC",
        "DOF_SECT_ACTDESC",
        "DOF_SECT_DIFOHDR",
        "DOF_SECT_DIF",
        "DOF_SECT_STRTAB",
        "DOF_SECT_VARTAB", 
        "DOF_SECT_RELTAB", 
        "DOF_SECT_TYPTAB", 
        "DOF_SECT_URELHDR", 
        "DOF_SECT_KRELHDR",
        "DOF_SECT_OPTDESC",
        "DOF_SECT_PROVIDER",
        "DOF_SECT_PROBES",
        "DOF_SECT_PRARGS", 
        "DOF_SECT_PROFFS", 
        "DOF_SECT_INTTAB", 
        "DOF_SECT_UTSNAME", 
        "DOF_SECT_XLTAB",
        "DOF_SECT_XLMEMBERS",
        "DOF_SECT_XLIMPORT",
        "DOF_SECT_XLEXPORT",
        "DOF_SECT_PREXPORT",
        "DOF_SECT_PRENOFFS"
    };
    
    if (type < 0 || type > 26) {
        return "none";
    }
    return t2s[type];
}

void print_probe(dof_probe_t *probe, char *strtab, int indent) {
    printf("%*s", indent, " ");
    printf("%s : %s\n", strtab + probe->dofpr_func, strtab + probe->dofpr_name);
    printf("%*snoffs(%d) - offidx(%d) - nenoffs(%d) - enoffidx(%d)\n", indent*2, " ", probe->dofpr_noffs, probe->dofpr_offidx, probe->dofpr_nenoffs, probe->dofpr_enoffidx);
}

int dtrace_dof_slurp(dof_hdr_t *dof) {
    uint64_t len = dof->dofh_loadsz, seclen;
    uint64_t daddr = (uint64_t)dof;
    char *strtab = NULL, *typestr;
//    dtrace_ecbdesc_t *ep;
//    dtrace_enabling_t *enab;
    uint_t i;
    

    assert(dof->dofh_loadsz >= sizeof (dof_hdr_t));
    
    /*
     * Check the DOF header identification bytes.  In addition to checking
     * valid settings, we also verify that unused bits/bytes are zeroed so
     * we can use them later without fear of regressing existing binaries.
     */
    if (bcmp(&dof->dofh_ident[DOF_ID_MAG0],
             DOF_MAG_STRING, DOF_MAG_STRLEN) != 0) {
        error("DOF magic string mismatch");
        return (-1);
    }
    
    if (dof->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_ILP32 &&
        dof->dofh_ident[DOF_ID_MODEL] != DOF_MODEL_LP64) {
        error( "DOF has invalid data model");
        return (-1);
    }
    
    if (dof->dofh_ident[DOF_ID_ENCODING] != DOF_ENCODE_NATIVE) {
        error( "DOF encoding mismatch");
        return (-1);
    }
    
    /*
     * APPLE NOTE: Darwin only supports DOF_VERSION_3 for now.
     */
    if (dof->dofh_ident[DOF_ID_VERSION] != DOF_VERSION_3) {
        error("DOF version mismatch");
        return (-1);
    }
    
    printf("DOF VERSIOIN: %d\n", dof->dofh_ident[DOF_ID_VERSION]);
    
    if (dof->dofh_ident[DOF_ID_DIFVERS] != DIF_VERSION_2) {
        error("DOF uses unsupported instruction set");
        return (-1);
    }
    
    if (dof->dofh_ident[DOF_ID_DIFIREG] > DIF_DIR_NREGS) {
        error("DOF uses too many integer registers");
        return (-1);
    }
    
    if (dof->dofh_ident[DOF_ID_DIFTREG] > DIF_DTR_NREGS) {
        error("DOF uses too many tuple registers");
        return (-1);
    }
    
    for (i = DOF_ID_PAD; i < DOF_ID_SIZE; i++) {
        if (dof->dofh_ident[i] != 0) {
            error("DOF has invalid ident byte set");
            return (-1);
        }
    }
    
    if (dof->dofh_flags & ~DOF_FL_VALID) {
        error( "DOF has invalid flag bits set");
        return (-1);
    }
    
    if (dof->dofh_secsize == 0) {
        error( "zero section header size");
        return (-1);
    }
    
    seclen = (uint64_t)dof->dofh_secnum * (uint64_t)dof->dofh_secsize;
    if (dof->dofh_secoff > len || seclen > len ||
        dof->dofh_secoff + seclen > len) {
        error("truncated section headers");
        return (-1);
    }
    
    /* 遍历 section */
    for (int i = 0; i < dof->dofh_secnum; i++) {
        dof_sec_t *sec = (dof_sec_t *)((uintptr_t)dof + (uintptr_t)dof->dofh_secoff + i * dof->dofh_secsize);
        printf("[%d] section type: %s\n", i, type_to_string(sec->dofs_type));
        switch (sec->dofs_type) {
            case DOF_SECT_STRTAB:
                strtab = (char *)daddr + sec->dofs_offset;
                break;
            case DOF_SECT_DIF:
            {
                printf("%d: dif\n", i);
            }
                break;
            case DOF_SECT_PROVIDER:
            {
                printf("    [provider]:\n");
                int num = (int)sec->dofs_size/sizeof(dof_provider_t);
                dof_provider_t *prov;
                for(int i = 0; i < num; i++) {
                    prov = (dof_provider_t *)(daddr + sec->dofs_offset + i * sizeof(dof_provider_t));
                    printf("    %s, dofpv_probes(%d), proffs(%d)\n", strtab + prov->dofpv_name, prov->dofpv_probes, prov->dofpv_proffs);
                }
            }
                break;
            case DOF_SECT_PROBES:
            {
                printf("%*sfunction : name\n", 4, " ");
                int num = (int)sec->dofs_size/sizeof(dof_probe_t);
                dof_probe_t *probe;
                for(int i = 0; i < num; i++) {
                    probe = (dof_probe_t *)(daddr + sec->dofs_offset + i * sizeof(dof_probe_t));
                    print_probe(probe, strtab, 4);
                }
            }
                break;
            case DOF_SECT_PROFFS:
            {
                int num = (int)(sec->dofs_size / sec->dofs_entsize);
                for (int j = 0; j < num; j++) {
                    uint32_t *p = (uint32_t *)(daddr + sec->dofs_offset + j* sec->dofs_entsize);
                    printf("%*s[%d] %d\n", 4, " ", j, *p);
                }
            }
                break;
            case DOF_SECT_ECBDESC:
                // ......
                break;
                
            default:
                break;
        }
    }
    
    return 0;
}

char *dof_str(char *strtab, dof_stridx_t idx) {
    return "";
}

size_t file_size(const char *path) {
    struct stat st;
    
    // stat() returns -1 on error. Skipping check in this example
    if (stat(path, &st) == -1) {
        perror("stat failed\n");
        return 0;
    }
    return (size_t)st.st_size;
}

void display_usage() {
    // TODO:
}

dof_hdr_t *dof_of_macho(struct mach_header_64 *macho) {
    
    // walk load commands (mapped in at start of __TEXT segment)
    const uint32_t cmd_count = (macho)->ncmds;
    const struct load_command* const cmds = (struct load_command *)&((char*)macho)[sizeof(struct mach_header_64)];
    const struct load_command* cmd = cmds;
    for (uint32_t i = 0; i < cmd_count; ++i) {
        switch (cmd->cmd) {
            case LC_SEGMENT_COMMAND:
            {
                const struct segment_command_64* seg = (struct segment_command_64*)cmd;
                const struct section_64* const sectionsStart = (struct section_64*)((char*)seg + sizeof(struct segment_command_64));
                const struct section_64* const sectionsEnd = &sectionsStart[seg->nsects];
                for (const struct section_64* sect=sectionsStart; sect < sectionsEnd; ++sect) {
                    if ( (sect->flags & SECTION_TYPE) == S_DTRACE_DOF ) {
                        // <rdar://problem/23929217> Ensure section is within segment
                        if ( (sect->addr < seg->vmaddr) || (sect->addr+sect->size > seg->vmaddr+seg->vmsize) || (sect->addr+sect->size < sect->addr) )
                            error("DOF section has malformed address range for\n");
                        
                    
                        return (void*)(sect->offset + (void*)macho);
                    }
                }
            }
                break;
        }
        cmd = (const struct load_command*)(((char*)cmd)+cmd->cmdsize);
    }
    
    return NULL;
}

int main(int argc, char * argv[]) {
    const char *path;
    char *buff;
    int opt = 0;
    
    //
    opt = getopt(argc, argv, optString );
    while( opt != -1 ) {
        switch( opt ) {
            case 'm':
                g_opt_macho = 1;
                break;
            case 'h':   /* fall-through is intentional */
            case '?':
                display_usage();
                break;
                
            default:
                /* You won't actually get here. */
                break;
        }
        opt = getopt( argc, argv, optString );
    }
    
    path = argv[optind];
    if (!path) {
        error("no dof file\n");
        exit(-1);
    }
    
    FILE *fd;
    if((fd = fopen(path, "r" )) == NULL ) {
        perror(argv[1]);
        exit(-1);
    }
    
    size_t size = file_size(path);
    if (size != 0) {
        buff = (char *)malloc(size + 1);
        if (!buff) {
            perror("malloc error");
            exit(-1);
        }
    }
    bzero((void *)buff, size + 1);
    
    /* read */
    fread(buff, size + 1, 1, fd);
    
    if (g_opt_macho) { // 读取 macho 中的 S_DTRACE_DOF
        dof_hdr_t * dof = dof_of_macho((struct mach_header_64 *)buff);
        if (!dof) {
            error("no dof section in %s\n", path);
            exit(-1);
        }
        dtrace_dof_slurp(dof);
    } else {
        dtrace_dof_slurp((dof_hdr_t *)buff);
    }
    
//    free(buff);
    return 0;
}
