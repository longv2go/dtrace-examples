//
//  main.c
//  usdt
//
//  Created by albert on 2018/1/18.
//  Copyright © 2018年 ant. All rights reserved.
//

#include "testp.h"

// sudo dtrace -n "syncengine_sync*::: {printf(\"Transitioning to state %d\n\", arg0);}"

int main(int argc, const char * argv[]) {
    
    printf("\n");
    SYNCENGINE_SYNC_STRATEGY_GO_TO_STATE(1);
    SYNCENGINE_SYNC_STRATEGY_LEAVE_STATE(2);
    printf("hello\n");
    SYNCENGINE_SYNC_STRATEGY_GO_TO_STATE(1);
    return 0;
}
