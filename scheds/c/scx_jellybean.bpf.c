/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) 2025 University of Wisconsin-Madison.
 * Copyright (c) 2022 Meta Platforms, Inc. and affiliates.
 * Copyright (c) 2022 Tejun Heo <tj@kernel.org>
 * Copyright (c) 2022 David Vernet <dvernet@meta.com>
 */
#include <scx/common.bpf.h>

#define SCHED_BATCH 3

char _license[] SEC("license") = "GPL";

const volatile bool fifo_sched;
volatile bool throttled;
volatile s64 batches;

static u64 vtime_now;
UEI_DEFINE(uei);

#define MAX_CPUS 1
#define SHARED_DSQ 0
#define BATCH_DSQ 1

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u64));
	__uint(max_entries, 4);
} stats SEC(".maps");

static void stat_inc(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p)++;
}

static void stat_set(u32 idx, u32 val)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	if (cnt_p)
		(*cnt_p) = val;
}

static u32 stat_get(u32 idx)
{
	u64 *cnt_p = bpf_map_lookup_elem(&stats, &idx);
	return cnt_p ? *cnt_p : 0;
}

s32 BPF_STRUCT_OPS(jellybean_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu;
	cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	if (is_idle && !(p->policy == SCHED_BATCH && throttled))
	{
		stat_inc(0);
		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
	}
	return cpu;
}

void BPF_STRUCT_OPS(jellybean_tick, struct task_struct *p)
{
	if (p->policy == SCHED_BATCH && throttled)
	{
		s32 cpu = scx_bpf_task_cpu(p);
		scx_bpf_kick_cpu(cpu, SCX_KICK_PREEMPT);
	}
}

void BPF_STRUCT_OPS(jellybean_enqueue, struct task_struct *p, u64 enq_flags)
{
	if (p->policy == SCHED_BATCH && throttled)
	{
		stat_inc(2);
		scx_bpf_dsq_insert(p, BATCH_DSQ, SCX_SLICE_DFL, enq_flags);
	}
	else if (fifo_sched)
	{
		stat_inc(1);
		scx_bpf_dsq_insert(p, SHARED_DSQ, SCX_SLICE_DFL, enq_flags);
	}
	else
	{
		u64 vtime = p->scx.dsq_vtime;
		if (time_before(vtime, vtime_now - SCX_SLICE_DFL))
			vtime = vtime_now - SCX_SLICE_DFL;

		scx_bpf_dsq_insert_vtime(p, SHARED_DSQ, SCX_SLICE_DFL, vtime,
								 enq_flags);
	}
}

void BPF_STRUCT_OPS(jellybean_dispatch, s32 cpu, struct task_struct *prev)
{

	if (!scx_bpf_dsq_move_to_local(SHARED_DSQ))
	{
		if (!throttled || cpu < MAX_CPUS)
		{
			scx_bpf_dsq_move_to_local(BATCH_DSQ);
		}
	}
}

void BPF_STRUCT_OPS(jellybean_running, struct task_struct *p)
{
	if (p->policy == SCHED_BATCH)
	{
		stat_set(3, 1);
	}
	if (fifo_sched)
		return;
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;
}

void BPF_STRUCT_OPS(jellybean_stopping, struct task_struct *p, bool runnable)
{
	if (p->policy == SCHED_BATCH)
	{
		stat_set(3, 0);
	}
	if (fifo_sched)
		return;

	p->scx.dsq_vtime += (SCX_SLICE_DFL - p->scx.slice) * 100 / p->scx.weight;
}

void BPF_STRUCT_OPS(jellybean_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(jellybean_init)
{
	s32 ret;
	if ((ret = scx_bpf_create_dsq(SHARED_DSQ, -1)) < 0)
		return ret;
	if ((ret = scx_bpf_create_dsq(BATCH_DSQ, -1)) < 0)
		return ret;
	// cpu_limit = 4;
	return ret;
}

void BPF_STRUCT_OPS(jellybean_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(jellybean_ops,
			   .select_cpu = (void *)jellybean_select_cpu,
			   .tick = (void *)jellybean_tick,
			   .enqueue = (void *)jellybean_enqueue,
			   .dispatch = (void *)jellybean_dispatch,
			   .running = (void *)jellybean_running,
			   .stopping = (void *)jellybean_stopping,
			   .enable = (void *)jellybean_enable,
			   .init = (void *)jellybean_init,
			   .exit = (void *)jellybean_exit,
			   .name = "jellybean");
