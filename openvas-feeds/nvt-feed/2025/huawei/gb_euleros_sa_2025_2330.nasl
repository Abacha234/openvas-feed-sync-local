# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2330");
  script_cve_id("CVE-2022-49110", "CVE-2022-49325", "CVE-2022-49803", "CVE-2022-49932", "CVE-2022-50098", "CVE-2022-50100", "CVE-2023-52927", "CVE-2023-53039", "CVE-2023-53105", "CVE-2023-53133", "CVE-2023-53421", "CVE-2024-2201", "CVE-2024-58100", "CVE-2024-58237", "CVE-2025-21738", "CVE-2025-22021", "CVE-2025-22055", "CVE-2025-22057", "CVE-2025-22075", "CVE-2025-22086", "CVE-2025-22103", "CVE-2025-37749", "CVE-2025-37756", "CVE-2025-37765", "CVE-2025-37789", "CVE-2025-37859", "CVE-2025-37959", "CVE-2025-37961", "CVE-2025-37989", "CVE-2025-37992", "CVE-2025-37998", "CVE-2025-38015", "CVE-2025-38031", "CVE-2025-38035", "CVE-2025-38040", "CVE-2025-38063", "CVE-2025-38067", "CVE-2025-38072", "CVE-2025-38079", "CVE-2025-38086", "CVE-2025-38103", "CVE-2025-38111", "CVE-2025-38115", "CVE-2025-38120", "CVE-2025-38124", "CVE-2025-38146", "CVE-2025-38147", "CVE-2025-38154", "CVE-2025-38162", "CVE-2025-38165", "CVE-2025-38166", "CVE-2025-38184", "CVE-2025-38192", "CVE-2025-38211", "CVE-2025-38212", "CVE-2025-38214", "CVE-2025-38215", "CVE-2025-38222", "CVE-2025-38264", "CVE-2025-38273", "CVE-2025-38298", "CVE-2025-38310", "CVE-2025-38312", "CVE-2025-38320", "CVE-2025-38334", "CVE-2025-38346", "CVE-2025-38352", "CVE-2025-38375", "CVE-2025-38386", "CVE-2025-38391", "CVE-2025-38393", "CVE-2025-38396", "CVE-2025-38399", "CVE-2025-38424", "CVE-2025-38449", "CVE-2025-38457", "CVE-2025-38464", "CVE-2025-38465", "CVE-2025-38466", "CVE-2025-38495", "CVE-2025-38498", "CVE-2025-38499", "CVE-2025-38516", "CVE-2025-38539", "CVE-2025-38563", "CVE-2025-38565", "CVE-2025-38574", "CVE-2025-38632", "CVE-2025-38668", "CVE-2025-38671", "CVE-2025-38695", "CVE-2025-39866");
  script_tag(name:"creation_date", value:"2025-11-12 04:29:57 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-06 17:27:39 +0000 (Thu, 06 Nov 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2330)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP12\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2330");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2330");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2330 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"tracing: Add down_write(trace_event_sem) when adding trace event(CVE-2025-38539)

tipc: fix null-ptr-deref when acquiring remote ip of ethernet bearer(CVE-2025-38184)

pinmux: fix race causing mux_owner NULL with active mux_usecount(CVE-2025-38632)

openvswitch: Fix unsafe attribute parsing in output_userspace()(CVE-2025-37998)

perf: Revert to requiring CAP_SYS_ADMIN for uprobes(CVE-2025-38466)

fbdev: Fix fb_set_var to prevent null-ptr-deref in fb_videomode_to_var(CVE-2025-38214)

posix-cpu-timers: fix race between handle_posix_cpu_timers() and posix_cpu_timer_del()(CVE-2025-38352)

padata: do not leak refcount in reorder_work(CVE-2025-38031)

rseq: Fix segfault on registration when rseq_cs is non-zero(CVE-2025-38067)

dm: fix unconditional IO throttle caused by REQ_PREFLUSH(CVE-2025-38063)

RDMA/mlx5: Fix mlx5_poll_one() cur_qp update flow(CVE-2025-22086)

HID: core: ensure the allocated report buffer can contain the reserved report ID(CVE-2025-38495)

net_sched: sch_sfq: fix a potential crash on gso_skb handling(CVE-2025-38115)

pinctrl: qcom: msm: mark certain pins as invalid for interrupts(CVE-2025-38516)

fs: export anon_inode_make_secure_inode() and fix secretmem LSM bypass(CVE-2025-38396)

ata: libata-sff: Ensure that we cannot write outside the allocated buffer(CVE-2025-21738)

HID: intel-ish-hid: ipc: Fix potential use-after-free in work function(CVE-2023-53039)

sched/core: Do not requeue task on CPU excluded from cpus_mask(CVE-2022-50100)

netfilter: nft_set_pipapo: prevent overflow in lookup table allocation(CVE-2025-38162)

fbdev: core: fbcvt: avoid division by 0 in fb_cvt_hperiod()(CVE-2025-38312)

clone_private_mnt(): make sure that caller has CAP_SYS_ADMIN in the right userns(CVE-2025-38499)

crypto: algif_hash - fix double free in hash_accept(CVE-2025-38079)

pptp: ensure minimal skb length in pptp_xmit()(CVE-2025-38574)

net: ch9200: fix uninitialised access during mii_nway_restart(CVE-2025-38086)

arm64/ptrace: Fix stack-out-of-bounds read in regs_get_kernel_stack_nth()(CVE-2025-38320)

net: openvswitch: Fix the dead loop of MPLS parse(CVE-2025-38146)

scsi: qla2xxx: Fix crash due to stale SRB access around I/O timeouts(CVE-2022-50098)

scsi: target: Fix NULL pointer dereference in core_scsi3_decode_spec_i_port()(CVE-2025-38399)

i2c: qup: jump out of the loop in case of timeout(CVE-2025-38671)

x86/sgx: Prevent attempts to reclaim poisoned pages(CVE-2025-38334)

nvmet-tcp: don't restore null(CVE-2025-38035)

net: fix udp gso skb_segment after pull from frag_list(CVE-2025-38124)

net/mlx5e: Fix cleanup null-ptr deref on encap lock(CVE-2023-53105)

net: fix NULL pointer dereference in l3mdev_l3_rcv(CVE-2025-22103)

do_change_type(): refuse to operate on unmounted/not ours mounts(CVE-2025-38498)

ext4: inline: fix len overflow in ext4_prepare_inline_data(CVE-2025-38222)

bpf: check changes_pkt_data property for extension programs(CVE-2024-58100)

bpf: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP12(x86_64).");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "EULEROS-2.0SP12-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~136.12.0.86.h2738.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~136.12.0.86.h2738.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~136.12.0.86.h2738.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~136.12.0.86.h2738.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~136.12.0.86.h2738.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~136.12.0.86.h2738.eulerosv2r12", rls:"EULEROS-2.0SP12-x86_64"))) {
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
