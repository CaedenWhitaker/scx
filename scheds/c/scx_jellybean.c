/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 University of Wisconsin-Madison.
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <libgen.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "scx_jellybean.bpf.skel.h"

const char help_fmt[] =
"A jellybean sched_ext scheduler.\n"
"\n"
"See the top-level comment in .bpf.c for more details.\n"
"\n"
"Usage: %s [-f] [-v]\n"
"\n"
"  -f            Use FIFO scheduling instead of weighted vtime scheduling\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

#define MEMORY_THRESHOLD 10000.0

static bool verbose;
static volatile int exit_req;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int simple)
{
	exit_req = 1;
}

static void read_stats(struct scx_jellybean *skel, __u64 *stats)
{
	int nr_cpus = libbpf_num_possible_cpus();
	__u64 cnts[4][nr_cpus];
	__u32 idx;

	memset(stats, 0, sizeof(stats[0]) * 4);

	for (idx = 0; idx < 4; idx++) {
		int ret, cpu;

		ret = bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats),
					  &idx, cnts[idx]);
		if (ret < 0)
			continue;
		for (cpu = 0; cpu < nr_cpus; cpu++)
			stats[idx] += cnts[idx][cpu];
	}
}

double get_memory_from_csv(const char *path, ssize_t *last_byte) {
	double result = 0;
	FILE *file;
	if((file = fopen(path, "r")) != NULL && fseek(file, *last_byte, SEEK_SET) == 0){
		size_t line_size = 0;
		char *line = NULL;
		ssize_t bytes_read = -1;
		int new_lines = 0;
		while((bytes_read = getline(&line, &line_size, file)) != -1){
			*last_byte += bytes_read;
			new_lines++;
		}
		if(new_lines){
			char *token;
			char *saveptr;
			token = strtok_r(line, ",", &saveptr);
			while (token != NULL) {
				result = strtod(token, NULL);
				if (errno == ERANGE) {
					result = 0;
					break;
				}
				token = strtok_r(NULL, ",", &saveptr);
			}
			free(line);
		}
		fclose(file);
	}
    return result;
}


int main(int argc, char **argv)
{
	struct scx_jellybean *skel;
	struct bpf_link *link;
	__u32 opt;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
restart:
	skel = SCX_OPS_OPEN(jellybean_ops, scx_jellybean);
	skel->bss->throttled = false;
	while ((opt = getopt(argc, argv, "fvh")) != -1) {
		switch (opt) {
		case 'f':
			skel->rodata->fifo_sched = true;
			break;
		case 'v':
			verbose = true;
			break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	SCX_OPS_LOAD(skel, jellybean_ops, scx_jellybean, uei);
	link = SCX_OPS_ATTACH(skel, jellybean_ops, scx_jellybean);
	
	ssize_t last_byte = 0;
	double memory = 0;
	bool throttled = false;
	ssize_t history = 0;

	for (__u64 i=0; !exit_req && !UEI_EXITED(skel, uei); i++) {
		if(i%1000==0){
			__u64 stats[4];
			read_stats(skel, stats);
			printf("local=%llu global=%llu batch=%llu cpus=%llu memory=%lf throttled=%s\n", stats[0], stats[1], stats[2], stats[3], memory, skel->bss->throttled ? "true" : "false");
			fflush(stdout);
		}
		memory = get_memory_from_csv("/tmp/memory.log", &last_byte);
		if(memory > MEMORY_THRESHOLD){
			history = 40;
			skel->bss->throttled = throttled = true;
		}else if(throttled){
			if(history) history--;
			else skel->bss->throttled = throttled = false;
		}
		usleep(500);
	}

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	scx_jellybean__destroy(skel);

	if (UEI_ECODE_RESTART(ecode))
		goto restart;
	return 0;
}
