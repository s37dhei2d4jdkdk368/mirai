#pragma once

void persistence_init(void);
const char* get_persistent_path(void);
void persistence_watchdog_init(void);
void persistence_check_health(void);
void persistence_watchdog_start(void);

