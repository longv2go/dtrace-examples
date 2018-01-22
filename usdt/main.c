//
//  main.c
//  usdt
//
//  Created by albert on 2018/1/18.
//  Copyright © 2018年 ant. All rights reserved.
//

#include <stdio.h>
#include "testp.h"

// sudo dtrace -n "syncengine_sync*::: {printf(\"Transitioning to state %d\n\", arg0);}"

int main(int argc, const char * argv[]) {
    printf("Hello, World!\n");
    SYNCENGINE_SYNC_STRATEGY_GO_TO_STATE(1);
    return 0;
}
