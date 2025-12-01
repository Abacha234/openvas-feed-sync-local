# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2390");
  script_cve_id("CVE-2022-49345", "CVE-2022-49575", "CVE-2022-49611", "CVE-2022-49727", "CVE-2022-49840", "CVE-2022-49917", "CVE-2022-49918", "CVE-2022-49981", "CVE-2022-50085", "CVE-2022-50134", "CVE-2022-50224", "CVE-2023-53053", "CVE-2023-53066", "CVE-2023-53109", "CVE-2024-58239", "CVE-2025-38222", "CVE-2025-38285", "CVE-2025-38324", "CVE-2025-38332", "CVE-2025-38386", "CVE-2025-38391", "CVE-2025-38415", "CVE-2025-38424", "CVE-2025-38445", "CVE-2025-38449", "CVE-2025-38474", "CVE-2025-38477", "CVE-2025-38494", "CVE-2025-38498", "CVE-2025-38499", "CVE-2025-38527", "CVE-2025-38617", "CVE-2025-38618", "CVE-2025-38700", "CVE-2025-38710", "CVE-2025-38724");
  script_tag(name:"creation_date", value:"2025-11-12 04:29:57 +0000 (Wed, 12 Nov 2025)");
  script_version("2025-11-13T05:40:19+0000");
  script_tag(name:"last_modification", value:"2025-11-13 05:40:19 +0000 (Thu, 13 Nov 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-12 18:00:35 +0000 (Wed, 12 Nov 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2390)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP10\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2390");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2390");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2390 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"net: xfrm: unexport __init-annotated xfrm4_protocol_init()(CVE-2022-49345)

tcp: Fix a data-race around sysctl_tcp_thin_linear_timeouts.(CVE-2022-49575)

x86/speculation: Fill RSB on vmexit for IBRS(CVE-2022-49611)

ipv6: Fix signed integer overflow in l2tp_ip6_sendmsg(CVE-2022-49727)

bpf, test_run: Fix alignment problem in bpf_prog_test_run_skb()(CVE-2022-49840)

ipvs: fix WARNING in ip_vs_app_net_cleanup() (CVE-2022-49917)

ipvs: fix WARNING in __ip_vs_cleanup_batch()(CVE-2022-49918)

HID: hidraw: fix memory leak in hidraw_release() (CVE-2022-49981)

dm raid: fix address sanitizer warning in raid_resume (CVE-2022-50085)

RDMA/hfi1: fix potential memory leak in setup_base_ctxt()(CVE-2022-50134)

KVM: x86/mmu: Treat NX as a valid SPTE bit for NPT(CVE-2022-50224)

erspan: do not use skb_mac_header() in ndo_start_xmit()(CVE-2023-53053)

qed/qed_sriov: guard against NULL derefs from qed_iov_get_vf_info(CVE-2023-53066)

net: tunnels: annotate lockless accesses to dev->needed_headroom(CVE-2023-53109)

tls: stop recv() if initial process_rx_list gave us non-DATA (CVE-2024-58239)

ext4: inline: fix len overflow in ext4_prepare_inline_data(CVE-2025-38222)

bpf: Fix WARN() in get_bpf_raw_tp_regs(CVE-2025-38285)

Use rcu_dereference_rtnl() in mpls_route_input_rcu().(CVE-2025-38324)

scsi: lpfc: Use memcpy() for BIOS version(CVE-2025-38332)

ACPICA: Refuse to evaluate a method if arguments are missing(CVE-2025-38386)

usb: typec: altmodes/displayport: do not index invalid pin_assignments(CVE-2025-38391)

Squashfs: check return result of sb_min_blocksize(CVE-2025-38415)

perf: Fix sample vs do_exit()(CVE-2025-38424)

md/raid1: Fix stack memory use after return in raid1_reshape(CVE-2025-38445)

drm/gem: Acquire references on GEM handles for framebuffers(CVE-2025-38449)

usb: net: sierra: check for no status endpoint(CVE-2025-38474)

net/sched: sch_qfq: Fix race condition on qfq_aggregate(CVE-2025-38477)

HID: core: do not bypass hid_hw_raw_request(CVE-2025-38494)

do_change_type(): refuse to operate on unmounted/not ours mounts(CVE-2025-38498)

clone_private_mnt(): make sure that caller has CAP_SYS_ADMIN in the right userns(CVE-2025-38499)

smb: client: fix use-after-free in cifs_oplock_break(CVE-2025-38527)

net/packet: fix a race in packet_set_ring() and packet_notifier()(CVE-2025-38617)

vsock: Do not allow binding to VMADDR_PORT_ANY(CVE-2025-38618)

scsi: libiscsi: Initialize iscsi_conn->dd_data only if memory is allocated(CVE-2025-38700)

gfs2: Validate i_depth for exhash directories(CVE-2025-38710)

nfsd: handle get_client_locked() failure in nfsd4_setclientid_confirm()(CVE-2025-38724)");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP10(x86_64).");

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

if(release == "EULEROS-2.0SP10-x86_64") {

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~4.18.0~147.5.2.19.h1906.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~4.18.0~147.5.2.19.h1906.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~4.18.0~147.5.2.19.h1906.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~4.18.0~147.5.2.19.h1906.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~4.18.0~147.5.2.19.h1906.eulerosv2r10", rls:"EULEROS-2.0SP10-x86_64"))) {
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
