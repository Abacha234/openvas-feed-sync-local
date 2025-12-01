# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2418");
  script_cve_id("CVE-2022-49840", "CVE-2022-49865", "CVE-2022-49892", "CVE-2022-49903", "CVE-2022-49907", "CVE-2022-49917", "CVE-2022-49918", "CVE-2022-49921", "CVE-2022-50022", "CVE-2022-50098", "CVE-2022-50103", "CVE-2023-53051", "CVE-2023-53053", "CVE-2023-53062", "CVE-2023-53066", "CVE-2023-53109", "CVE-2023-53125", "CVE-2024-57982", "CVE-2025-22055", "CVE-2025-37932", "CVE-2025-38000", "CVE-2025-38063", "CVE-2025-38079", "CVE-2025-38086", "CVE-2025-38212", "CVE-2025-38222", "CVE-2025-38285", "CVE-2025-38312", "CVE-2025-38337", "CVE-2025-38386", "CVE-2025-38424", "CVE-2025-38499");
  script_tag(name:"creation_date", value:"2025-11-12 04:29:57 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-12 18:00:35 +0000 (Wed, 12 Nov 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2418)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2418");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2418");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2418 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"bpf, test_run: Fix alignment problem in bpf_prog_test_run_skb()(CVE-2022-49840)

ipv6: addrlabel: fix infoleak when sending struct ifaddrlblmsg to network(CVE-2022-49865)

ftrace: Fix use-after-free for dynamic ftrace_ops(CVE-2022-49892)

ipv6: fix WARNING in ip6_route_net_exit_late()(CVE-2022-49903)

net: mdio: fix undefined behavior in bit shift for __mdiobus_register(CVE-2022-49907)

ipvs: fix WARNING in ip_vs_app_net_cleanup() (CVE-2022-49917)

ipvs: fix WARNING in __ip_vs_cleanup_batch()(CVE-2022-49918)

net: sched: Fix use after free in red_enqueue()(CVE-2022-49921)

drivers:md:fix a potential use-after-free bug(CVE-2022-50022)

scsi: qla2xxx: Fix crash due to stale SRB access around I/O timeouts(CVE-2022-50098)

sched, cpuset: Fix dl_cpu_busy() panic due to empty cs->cpus_allowed(CVE-2022-50103)

dm crypt: add cond_resched() to dmcrypt_write()(CVE-2023-53051)

erspan: do not use skb_mac_header() in ndo_start_xmit()(CVE-2023-53053)

net: usb: smsc95xx: Limit packet length to skb->len(CVE-2023-53062)

qed/qed_sriov: guard against NULL derefs from qed_iov_get_vf_info(CVE-2023-53066)

net: tunnels: annotate lockless accesses to dev->needed_headroom(CVE-2023-53109)

net: usb: smsc75xx: Limit packet length to skb->len(CVE-2023-53125)

xfrm: state: fix out-of-bounds read during lookup(CVE-2024-57982)

net: fix geneve_opt length integer overflow(CVE-2025-22055)

sch_htb: make htb_qlen_notify() idempotent(CVE-2025-37932)

sch_hfsc: Fix qlen accounting bug when using peek in hfsc_enqueue()(CVE-2025-38000)

dm: fix unconditional IO throttle caused by REQ_PREFLUSH(CVE-2025-38063)

crypto: algif_hash - fix double free in hash_accept(CVE-2025-38079)

net: ch9200: fix uninitialised access during mii_nway_restart(CVE-2025-38086)

ipc: fix to protect IPCS lookups using RCU(CVE-2025-38212)

ext4: inline: fix len overflow in ext4_prepare_inline_data(CVE-2025-38222)

bpf: Fix WARN() in get_bpf_raw_tp_regs(CVE-2025-38285)

fbdev: core: fbcvt: avoid division by 0 in fb_cvt_hperiod()(CVE-2025-38312)

jbd2: fix data-race and null-ptr-deref in jbd2_journal_dirty_metadata()(CVE-2025-38337)

ACPICA: Refuse to evaluate a method if arguments are missing(CVE-2025-38386)

perf: Fix sample vs do_exit()(CVE-2025-38424)

clone_private_mnt(): make sure that caller has CAP_SYS_ADMIN in the right userns(CVE-2025-38499)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10.");

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

if(release == "EULEROS-2.0SP10") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.19.90~vhulk2211.3.0.h2075.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.19.90~vhulk2211.3.0.h2075.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.19.90~vhulk2211.3.0.h2075.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.19.90~vhulk2211.3.0.h2075.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.19.90~vhulk2211.3.0.h2075.eulerosv2r10", rls:"EULEROS-2.0SP10"))) {
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
