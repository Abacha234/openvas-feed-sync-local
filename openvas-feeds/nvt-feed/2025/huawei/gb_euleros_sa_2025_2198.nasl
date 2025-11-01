# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2198");
  script_cve_id("CVE-2022-49266", "CVE-2022-49557", "CVE-2022-49803", "CVE-2022-49967", "CVE-2022-50098", "CVE-2022-50100", "CVE-2022-50167", "CVE-2022-50230", "CVE-2022-50232", "CVE-2023-52927", "CVE-2023-53039", "CVE-2023-53068", "CVE-2023-53105", "CVE-2024-2201", "CVE-2024-57841", "CVE-2024-58098", "CVE-2024-58100", "CVE-2025-21701", "CVE-2025-21738", "CVE-2025-21817", "CVE-2025-22008", "CVE-2025-22021", "CVE-2025-22055", "CVE-2025-22057", "CVE-2025-22075", "CVE-2025-22086", "CVE-2025-22103", "CVE-2025-23142", "CVE-2025-37749", "CVE-2025-37756", "CVE-2025-37757", "CVE-2025-37788", "CVE-2025-37789", "CVE-2025-37797", "CVE-2025-37798", "CVE-2025-37823", "CVE-2025-37824", "CVE-2025-37859", "CVE-2025-37862", "CVE-2025-37890", "CVE-2025-37913", "CVE-2025-37915", "CVE-2025-37920", "CVE-2025-37932", "CVE-2025-37948", "CVE-2025-37959", "CVE-2025-37961", "CVE-2025-37989", "CVE-2025-37992", "CVE-2025-37997", "CVE-2025-37998", "CVE-2025-38000", "CVE-2025-38001", "CVE-2025-38014", "CVE-2025-38044", "CVE-2025-38052", "CVE-2025-38061", "CVE-2025-38063", "CVE-2025-38066", "CVE-2025-38067", "CVE-2025-38068", "CVE-2025-38072", "CVE-2025-38074", "CVE-2025-38075", "CVE-2025-38083", "CVE-2025-38084", "CVE-2025-38086", "CVE-2025-38100", "CVE-2025-38102", "CVE-2025-38108", "CVE-2025-38111", "CVE-2025-38115", "CVE-2025-38120", "CVE-2025-38124", "CVE-2025-38127", "CVE-2025-38162", "CVE-2025-38166", "CVE-2025-38184", "CVE-2025-38192", "CVE-2025-38211", "CVE-2025-38214", "CVE-2025-38215", "CVE-2025-38222", "CVE-2025-38229", "CVE-2025-38273", "CVE-2025-38285", "CVE-2025-38320", "CVE-2025-38324", "CVE-2025-38337", "CVE-2025-38346", "CVE-2025-38352", "CVE-2025-38375", "CVE-2025-38386", "CVE-2025-38391", "CVE-2025-38399", "CVE-2025-38449", "CVE-2025-38457", "CVE-2025-38464", "CVE-2025-38466", "CVE-2025-38495", "CVE-2025-38498");
  script_tag(name:"creation_date", value:"2025-10-13 04:28:28 +0000 (Mon, 13 Oct 2025)");
  script_version("2025-10-30T05:40:01+0000");
  script_tag(name:"last_modification", value:"2025-10-30 05:40:01 +0000 (Thu, 30 Oct 2025)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-10-28 20:07:18 +0000 (Tue, 28 Oct 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2198)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2198");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2198");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2198 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"do_change_type(): refuse to operate on unmounted/not ours mounts(CVE-2025-38498)

HID: core: ensure the allocated report buffer can contain the reserved report ID(CVE-2025-38495)

perf: Revert to requiring CAP_SYS_ADMIN for uprobes(CVE-2025-38466)

tipc: Fix use-after-free in tipc_conn_close().(CVE-2025-38464)

net/sched: Abort __tc_modify_qdisc if parent class does not exist(CVE-2025-38457)

drm/gem: Acquire references on GEM handles for framebuffers(CVE-2025-38449)

scsi: target: Fix NULL pointer dereference in core_scsi3_decode_spec_i_port()(CVE-2025-38399)

usb: typec: altmodes/displayport: do not index invalid pin_assignments(CVE-2025-38391)

ACPICA: Refuse to evaluate a method if arguments are missing(CVE-2025-38386)

virtio-net: ensure the received length does not exceed allocated size(CVE-2025-38375)

posix-cpu-timers: fix race between handle_posix_cpu_timers() and posix_cpu_timer_del()(CVE-2025-38352)

ftrace: Fix UAF when lookup kallsym after ftrace disabled(CVE-2025-38346)

jbd2: fix data-race and null-ptr-deref in jbd2_journal_dirty_metadata()(CVE-2025-38337)

mpls: Use rcu_dereference_rtnl() in mpls_route_input_rcu().(CVE-2025-38324)

arm64/ptrace: Fix stack-out-of-bounds read in regs_get_kernel_stack_nth()(CVE-2025-38320)

bpf: Fix WARN() in get_bpf_raw_tp_regs(CVE-2025-38285)

net: tipc: fix refcount warning in tipc_aead_encrypt(CVE-2025-38273)

media: cxusb: no longer judge rbuf when the write fails(CVE-2025-38229)

ext4: inline: fix len overflow in ext4_prepare_inline_data(CVE-2025-38222)

fbdev: Fix do_register_framebuffer to prevent null-ptr-deref in fb_videomode_to_var(CVE-2025-38215)

fbdev: Fix fb_set_var to prevent null-ptr-deref in fb_videomode_to_var(CVE-2025-38214)

RDMA/iwcm: Fix use-after-free of work objects after cm_id destruction(CVE-2025-38211)

net: clear the dst when changing skb protocol(CVE-2025-38192)

tipc: fix null-ptr-deref when acquiring remote ip of ethernet bearer(CVE-2025-38184)

bpf: fix ktls panic with sockmap(CVE-2025-38166)

netfilter: nft_set_pipapo: prevent overflow in lookup table allocation(CVE-2025-38162)

ice: fix Tx scheduler error handling in XDP callback(CVE-2025-38127)

net: fix udp gso skb_segment after pull from frag_list(CVE-2025-38124)

netfilter: nf_set_pipapo_avx2: fix initial map fill(CVE-2025-38120)

net_sched: sch_sfq: fix a potential crash on gso_skb handling(CVE-2025-38115)

net/mdiobus: Fix potential out-of-bounds read/write access(CVE-2025-38111)

net_sched: red: fix a race in __red_change()(CVE-2025-38108)

VMCI: fix race between vmci_host_setup_notify and vmci_ctx_unset_notify(CVE-2025-38102)

x86/iopl: Cure TIF_IO_BITMAP inconsistencies(CVE-2025-38100)

net: ch9200: fix uninitialised access during mii_nway_restart(CVE-2025-38086)

mm/hugetlb: unshare page tables during VMA split, not before(CVE-2025-38084)

net_sched: prio: fix a race in prio_tune()(CVE-2025-38083)

scsi: target: iscsi: Fix timeout ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11(x86_64).");

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

if(release == "EULEROS-2.0SP11-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h1997.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h1997.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h1997.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h1997.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h1997.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h1997.eulerosv2r11", rls:"EULEROS-2.0SP11-x86_64"))) {
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
