#pragma once

struct Maat_garbage_bin{};
struct Maat_garbage_bin* Maat_garbage_bin_new(int default_timeout);
void Maat_garbage_bin_free(struct Maat_garbage_bin* bin);
void Maat_garbage_bagging(struct Maat_garbage_bin* bin, void* garbage, void (* func)(void *));
void Maat_garbage_collect_routine(struct Maat_garbage_bin* bin);
size_t  Maat_garbage_bin_get_size(struct Maat_garbage_bin* bin);
void Maat_garbage_collect_by_force(struct Maat_garbage_bin* bin);

