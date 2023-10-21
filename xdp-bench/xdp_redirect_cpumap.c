// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */

#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <getopt.h>
#include <locale.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <sys/sysinfo.h>
#include <linux/limits.h>
#include <sys/resource.h>
#include <linux/if_link.h>
#include <xdp/libxdp.h>

#include "logging.h"

#include "xdp-bench.h"
#include "xdp_sample.h"
#include "xdp_redirect_cpumap.skel.h"

static int map_fd;
static int avail_fd;
static int count_fd;

static int mask = SAMPLE_RX_CNT | SAMPLE_REDIRECT_ERR_MAP_CNT |
		  SAMPLE_CPUMAP_ENQUEUE_CNT | SAMPLE_CPUMAP_KTHREAD_CNT |
		  SAMPLE_EXCEPTION_CNT;

const struct cpumap_opts defaults_redirect_cpumap = {
	.mode = XDP_MODE_NATIVE,
	.interval = 2,
	.qsize = 2048,
	.program_mode = CPUMAP_CPU_SPI,
};

static const char *cpumap_prog_names[] = {
	"cpumap_no_touch",
	"cpumap_touch_data",
	"cpumap_round_robin",
	"cpumap_l4_proto",
	"cpumap_l4_filter",
	"cpumap_l4_hash",
	"cpumap_l4_sport",
	"cpumap_l4_dport",
	"cpumap_xfrm_spi",
};

DEFINE_SAMPLE_INIT(xdp_redirect_cpumap);

static int create_cpu_entry(__u32 cpu, struct bpf_cpumap_val *value,
			    __u32 avail_idx, bool new)
{
	__u32 curr_cpus_count = 0;
	__u32 key = 0;
	int ret;

	/* Add a CPU entry to cpumap, as this allocate a cpu entry in
	 * the kernel for the cpu.
	 */
	ret = bpf_map_update_elem(map_fd, &cpu, value, 0);
	if (ret < 0) {
		pr_warn("Create CPU entry failed: %s\n", strerror(errno));
		return ret;
	}

	/* Inform bpf_prog's that a new CPU is available to select
	 * from via some control maps.
	 */
	ret = bpf_map_update_elem(avail_fd, &avail_idx, &cpu, 0);
	if (ret < 0) {
		pr_warn("Add to avail CPUs failed: %s\n", strerror(errno));
		return ret;
	}

	/* When not replacing/updating existing entry, bump the count */
	ret = bpf_map_lookup_elem(count_fd, &key, &curr_cpus_count);
	if (ret < 0) {
		pr_warn("Failed reading curr cpus_count: %s\n",
			strerror(errno));
		return ret;
	}
	if (new) {
		curr_cpus_count++;
		ret = bpf_map_update_elem(count_fd, &key,
					  &curr_cpus_count, 0);
		if (ret < 0) {
			pr_warn("Failed write curr cpus_count: %s\n",
				strerror(errno));
			return ret;
		}
	}

	pr_debug("%s CPU: %u as idx: %u qsize: %d cpumap_prog_fd: %d (cpus_count: %u)\n",
		 new ? "Add new" : "Replace", cpu, avail_idx,
		 value->qsize, value->bpf_prog.fd, curr_cpus_count);

	return 0;
}

/* CPUs are zero-indexed. Thus, add a special sentinel default value
 * in map cpus_available to mark CPU index'es not configured
 */
static int mark_cpus_unavailable(void)
{
	int ret, i, n_cpus = libbpf_num_possible_cpus();
	__u32 invalid_cpu = n_cpus;

	for (i = 0; i < n_cpus; i++) {
		ret = bpf_map_update_elem(avail_fd, &i,
					  &invalid_cpu, 0);
		if (ret < 0) {
			pr_warn("Failed marking CPU unavailable: %s\n",
				strerror(errno));
			return ret;
		}
	}

	return 0;
}

/* Stress cpumap management code by concurrently changing underlying cpumap */
static void stress_cpumap(void *ctx)
{
	struct bpf_cpumap_val *value = ctx;

	/* Changing qsize will cause kernel to free and alloc a new
	 * bpf_cpu_map_entry, with an associated/complicated tear-down
	 * procedure.
	 */
	value->qsize = 1024;
	create_cpu_entry(1, value, 0, false);
	value->qsize = 8;
	create_cpu_entry(1, value, 0, false);
	value->qsize = 16000;
	create_cpu_entry(1, value, 0, false);
}

static int set_cpumap_prog(struct xdp_redirect_cpumap *skel,
			   enum cpumap_remote_action action,
			   const struct iface *redir_iface)
{
	struct bpf_devmap_val val = {};
	__u32 key = 0;
	int err;

	switch (action) {
	case ACTION_DISABLED:
		return 0;
	case ACTION_DROP:
		return bpf_program__fd(skel->progs.cpumap_drop);
	case ACTION_PASS:
		return bpf_program__fd(skel->progs.cpumap_pass);
	case ACTION_REDIRECT:
		break;
	default:
		return -EINVAL;
	}

	if (!redir_iface->ifindex) {
		pr_warn("Must specify redirect device when using --remote-action 'redirect'\n");
		return -EINVAL;
	}

	if (get_mac_addr(redir_iface->ifindex, skel->bss->tx_mac_addr) < 0) {
		pr_warn("Couldn't get MAC address for interface %s\n", redir_iface->ifname);
		return -EINVAL;
	}

	val.ifindex = redir_iface->ifindex;
	val.bpf_prog.fd = bpf_program__fd(skel->progs.redirect_egress_prog);

	err = bpf_map_update_elem(bpf_map__fd(skel->maps.tx_port), &key, &val, 0);
	if (err < 0)
		return -errno;

	return bpf_program__fd(skel->progs.cpumap_redirect);
}

static int parse_cpu_mask_str(const char *s, bool **mask, int *mask_sz)
{
        int err = 0, n, len, start, end = -1;
        bool *tmp;

        *mask = NULL;
        *mask_sz = 0;

        /* Each sub string separated by ',' has format \d+-\d+ or \d+ */
        while (*s) {
                if (*s == ',' || *s == '\n') {
                        s++;
                        continue;
                }
                n = sscanf(s, "%d%n-%d%n", &start, &len, &end, &len);
                if (n <= 0 || n > 2) {
                        pr_warn("Failed to get CPU range %s: %d\n", s, n);
                        err = -EINVAL;
                        goto cleanup;
                } else if (n == 1) {
                        end = start;
                }
                if (start < 0 || start > end) {
                        pr_warn("Invalid CPU range [%d,%d] in %s\n",
                                start, end, s);
                        err = -EINVAL;
                        goto cleanup;
                }
                tmp = realloc(*mask, end + 1);
                if (!tmp) {
                        err = -ENOMEM;
                        goto cleanup;
                }
                *mask = tmp;
                memset(tmp + *mask_sz, 0, start - *mask_sz);
                memset(tmp + start, 1, end - start + 1);
                *mask_sz = end + 1;
                s += len;
        }
        if (!*mask_sz) {
                pr_warn("Empty CPU range\n");
                return -EINVAL;
        }
        return 0;
cleanup:
        free(*mask);
        *mask = NULL;
        return err;
}

int parse_cpu_mask_file(const char *fcpu, bool **mask, int *mask_sz)
{
        int fd, err = 0;
        char buf[128];
        size_t len;

        fd = open(fcpu, O_RDONLY | O_CLOEXEC);
        if (fd < 0) {
                err = -errno;
                pr_warn("Failed to open cpu mask file %s: %d\n", fcpu, err);
                return err;
        }
        len = read(fd, buf, sizeof(buf));
        close(fd);
        if (len <= 0) {
                err = len ? -errno : -EINVAL;
                pr_warn("Failed to read cpu mask from %s: %d\n", fcpu, err);
                return err;
        }
        if (len >= sizeof(buf)) {
                pr_warn("CPU mask is too big in file %s\n", fcpu);
                return -E2BIG;
        }
        buf[len] = '\0';

        return parse_cpu_mask_str(buf, mask, mask_sz);
}

int do_redirect_cpumap(const void *cfg, __unused const char *pin_root_path)
{
        const char *online_cpus_file = "/sys/devices/system/cpu/online";
	const struct cpumap_opts *opt = cfg;
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct xdp_program *xdp_prog = NULL;
	struct xdp_redirect_cpumap *skel;
	struct bpf_program *prog = NULL;
	struct bpf_map_info info = {};
	struct bpf_cpumap_val value;
	__u32 infosz = sizeof(info);
	int ret = EXIT_FAIL_OPTION;
        __u32 n_online_cpus = 0;
        int online_cpus_sz;
        bool *online_cpus;
	int n_cpus, fd;
	size_t i;

	if (opt->extended)
		sample_switch_mode();

	if (opt->stats)
		mask |= SAMPLE_REDIRECT_MAP_CNT;

	if (opt->redir_iface.ifindex)
		mask |= SAMPLE_DEVMAP_XMIT_CNT_MULTI;

	n_cpus = libbpf_num_possible_cpus();

	/* Notice: Choosing the queue size is very important when CPU is
	 * configured with power-saving states.
	 *
	 * If deepest state take 133 usec to wakeup from (133/10^6). When link
	 * speed is 10Gbit/s ((10*10^9/8) in bytes/sec). How many bytes can
	 * arrive with in 133 usec at this speed: (10*10^9/8)*(133/10^6) =
	 * 166250 bytes. With MTU size packets this is 110 packets, and with
	 * minimum Ethernet (MAC-preamble + intergap) 84 bytes is 1979 packets.
	 *
	 * Setting default cpumap queue to 2048 as worst-case (small packet)
	 * should be +64 packet due kthread wakeup call (due to xdp_do_flush)
	 * worst-case is 2043 packets.
	 *
	 * Sysadm can configured system to avoid deep-sleep via:
	 *   tuned-adm profile network-latency
	 */


	skel = xdp_redirect_cpumap__open();
	if (!skel) {
		pr_warn("Failed to xdp_redirect_cpumap__open: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	/* Make sure we only load the one XDP program we are interested in */
	while ((prog = bpf_object__next_program(skel->obj, prog)) != NULL)
		if (bpf_program__type(prog) == BPF_PROG_TYPE_XDP &&
		    bpf_program__expected_attach_type(prog) == BPF_XDP)
			bpf_program__set_autoload(prog, false);

	prog = bpf_object__find_program_by_name(skel->obj,
						cpumap_prog_names[opt->program_mode]);
	if (!prog) {
		pr_warn("Failed to find program '%s'\n",
			cpumap_prog_names[opt->program_mode]);
		goto end_destroy;
	}

	ret = sample_init_pre_load(skel, opt->iface_in.ifname);
	if (ret < 0) {
		pr_warn("Failed to sample_init_pre_load: %s\n", strerror(-ret));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (bpf_map__set_max_entries(skel->maps.cpu_map, n_cpus) < 0) {
		pr_warn("Failed to set max entries for cpu_map map: %s",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	if (bpf_map__set_max_entries(skel->maps.cpus_available, n_cpus) < 0) {
		pr_warn("Failed to set max entries for cpus_available map: %s",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	ret = EXIT_FAIL_OPTION;

	skel->rodata->from_match[0] = opt->iface_in.ifindex;
	if (opt->redir_iface.ifindex)
		skel->rodata->to_match[0] = opt->redir_iface.ifindex;

	opts.obj = skel->obj;
	opts.prog_name = bpf_program__name(prog);
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		ret = -errno;
		pr_warn("Couldn't open XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	/* We always set the frags support bit: nothing the program does is
	 * incompatible with multibuf, and it's perfectly fine to load a program
	 * with frags support on an interface with a small MTU. We don't risk
	 * setting any flags the kernel will balk at, either, since libxdp will
	 * do the feature probing for us and skip the flag if the kernel doesn't
	 * support it.
	 *
	 * The function below returns EOPNOTSUPP it libbpf is too old to support
	 * setting the flags, but we just ignore that, since in such a case the
	 * best we can do is just attempt to run without the frags support.
	 */
	xdp_program__set_xdp_frags_support(xdp_prog, true);

	ret = xdp_program__attach(xdp_prog, opt->iface_in.ifindex, opt->mode, 0);
	if (ret < 0) {
		pr_warn("Failed to attach XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	ret = bpf_obj_get_info_by_fd(bpf_map__fd(skel->maps.cpu_map), &info, &infosz);
	if (ret < 0) {
		pr_warn("Failed bpf_obj_get_info_by_fd for cpumap: %s\n",
			strerror(errno));
		goto end_detach;
	}

	skel->bss->cpumap_map_id = info.id;

	map_fd = bpf_map__fd(skel->maps.cpu_map);
	avail_fd = bpf_map__fd(skel->maps.cpus_available);
	count_fd = bpf_map__fd(skel->maps.cpus_count);

	ret = mark_cpus_unavailable();
	if (ret < 0) {
		pr_warn("Unable to mark CPUs as unavailable\n");
		goto end_detach;
	}

	ret = sample_init(skel, mask, opt->iface_in.ifindex, 0);
	if (ret < 0) {
		pr_warn("Failed to initialize sample: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}

	fd = set_cpumap_prog(skel, opt->remote_action, &opt->redir_iface);
	if (fd < 0) {
		ret = EXIT_FAIL_BPF;
		goto end_detach;
	}
	value.qsize = opt->qsize;
	value.bpf_prog.fd = fd;

	if (opt->cpus.num_vals) {
                n_online_cpus = opt->cpus.num_vals;
		for (i = 0; i < opt->cpus.num_vals; i++) {
			if (create_cpu_entry(opt->cpus.vals[i], &value, i, true) < 0) {
				pr_warn("Cannot proceed, exiting\n");
				ret = EXIT_FAIL;
				goto end_detach;
			}
		}
	}

	if (opt->cpus_all) {
		int j, err;

                err = parse_cpu_mask_file(online_cpus_file, &online_cpus, &online_cpus_sz);
                if (err) {
                        pr_warn("Failed to get online CPUs, err=%d\n", err);
                        ret = EXIT_FAIL;
                        goto end;
                }

                n_online_cpus = 0;
		for (j = 0; j < min(n_cpus, online_cpus_sz); j++) {
                        if (!online_cpus[j])
                                continue;
			if (create_cpu_entry(j, &value, n_online_cpus, true) < 0) {
				pr_warn("Cannot proceed, exiting\n");
				ret = EXIT_FAIL;
				goto end_detach;
			}
                        n_online_cpus++;
		}
	}

	pr_debug("AA %s %d Max CPUS %u available CPUS %d%s\n", __func__, __LINE__, n_online_cpus, n_cpus,
			opt->cpus_all ? " use all cpus" : "");

	ret = sample_run(opt->interval, opt->stress_mode ? stress_cpumap : NULL, &value);
	if (ret < 0) {
		pr_warn("Failed during sample run: %s\n", strerror(-ret));
		ret = EXIT_FAIL;
		goto end_detach;
	}
	ret = EXIT_OK;
end_detach:
	xdp_program__detach(xdp_prog, opt->iface_in.ifindex, opt->mode, 0);
end_destroy:
	xdp_program__close(xdp_prog);
	xdp_redirect_cpumap__destroy(skel);
end:
	sample_teardown();
	return ret;
}
