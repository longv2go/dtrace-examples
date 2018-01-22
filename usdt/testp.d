provider syncengine_sync {
    probe operation_loop_enqueue(int, int, intptr_t);
    probe operation_loop_push_channel_data(int, int);
    probe strategy_go_to_state(int);
    probe strategy_leave_state(int);
    probe strategy_update_event(int, int);
    probe strategy_update_event_string(int, char *);
};

provider syncengine_ui {
    probe notification(int, intptr_t, char *, char *, int, int, int, int);
};
