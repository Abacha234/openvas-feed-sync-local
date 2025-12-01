# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2436");
  script_cve_id("CVE-2024-6174");
  script_tag(name:"creation_date", value:"2025-11-21 04:26:30 +0000 (Fri, 21 Nov 2025)");
  script_version("2025-11-21T05:40:28+0000");
  script_tag(name:"last_modification", value:"2025-11-21 05:40:28 +0000 (Fri, 21 Nov 2025)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2436)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2436");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2436");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2436 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"KVM: VMX: Do _all_ initialization before exposing /dev/kvm to userspace(CVE-2022-49932)

drivers:md:fix a potential use-after-free bug(CVE-2022-50022)

ceph: don't leak snap_rwsem in handle_cap_grant(CVE-2022-50059)

posix-cpu-timers: Cleanup CPU timers before freeing them during exec(CVE-2022-50095)

scsi: qla2xxx: Fix crash due to stale SRB access around I/O timeouts(CVE-2022-50098)

sched/core: Do not requeue task on CPU excluded from cpus_mask(CVE-2022-50100)

sched, cpuset: Fix dl_cpu_busy() panic due to empty cs->cpus_allowed(CVE-2022-50103)

An issue was discovered in drivers/tty/n_gsm.c in the Linux kernel 6.2. There is a sleeping function called from an invalid context in gsmld_write, which will block the kernel. Note: This has been disputed by 3rd parties as not a valid vulnerability.(CVE-2023-31082)

scsi: qla2xxx: Perform lockless command completion in abort path(CVE-2023-53041)

drm/nouveau: prime: fix ttm_bo_delayed_delete oops(CVE-2025-37765)

dmaengine: idxd: fix memory leak in error handling path of idxd_alloc(CVE-2025-38015)

padata: do not leak refcount in reorder_work(CVE-2025-38031)

nvmet-tcp: don't restore null sk_state_change(CVE-2025-38035)

rseq: Fix segfault on registration when rseq_cs is non-zero(CVE-2025-38067)

libnvdimm/labels: Fix divide error in nd_label_data_init()(CVE-2025-38072)

HID: usbhid: Eliminate recurrent out-of-bounds bug in usbhid_parse()(CVE-2025-38103)

net: openvswitch: Fix the dead loop of MPLS parse(CVE-2025-38146)

calipso: Don't call calipso functions for AF_INET sk.(CVE-2025-38147)

tipc: fix null-ptr-deref when acquiring remote ip of ethernet bearer(CVE-2025-38184)

net: clear the dst when changing skb protocol(CVE-2025-38192)

ipc: fix to protect IPCS lookups using RCU(CVE-2025-38212)

fbdev: Fix do_register_framebuffer to prevent null-ptr-deref in fb_videomode_to_var(CVE-2025-38215)

sched/rt: Fix race in push_rt_task(CVE-2025-38234)

nvme-tcp: sanitize request list handling(CVE-2025-38264)

net: tipc: fix refcount warning in tipc_aead_encrypt(CVE-2025-38273)

fbdev: core: fbcvt: avoid division by 0 in fb_cvt_hperiod()(CVE-2025-38312)

arm64/ptrace: Fix stack-out-of-bounds read in regs_get_kernel_stack_nth()(CVE-2025-38320)

virtio-net: ensure the received length does not exceed allocated size(CVE-2025-38375)

NFSv4/pNFS: Fix a race to wake on NFS_LAYOUT_DRAIN(CVE-2025-38393)

perf: Fix sample vs do_exit()(CVE-2025-38424)

net/sched: Abort __tc_modify_qdisc if parent class does not exist(CVE-2025-38457)

tipc: Fix use-after-free in tipc_conn_close().(CVE-2025-38464)

netlink: Fix wraparounds of sk->sk_rmem_alloc.(CVE-2025-38465)

perf: Revert to requiring CAP_SYS_ADMIN for uprobes(CVE-2025-38466)

do_change_type(): refuse to operate on unmounted/not ours mounts(CVE-2025-38498)

tracing: Add down_write(trace_event_sem) when adding trace event(CVE-2025-38539)

perf/core: Prevent VMA split of buffer ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP13(x86_64).");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP13-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"cloud-init", rpm:"cloud-init~19.4~2.h12.eulerosv2r10", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);
