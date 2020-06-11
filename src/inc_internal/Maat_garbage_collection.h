#pragma once

struct Maat_garbage_bin{};
struct Maat_garbage_bin* Maat_garbage_bin_new(void);
void Maat_garbage_bin_free(struct Maat_garbage_bin* bin);
void Maat_garbage_bag(struct Maat_garbage_bin* bin, void* garbage, int timeout, void (* func)(void *));
void Maat_garbage_collect_routine(struct Maat_garbage_bin* bin);

