# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2483");
  script_cve_id("CVE-2022-49158", "CVE-2022-49159", "CVE-2022-49325", "CVE-2022-49932", "CVE-2022-50267", "CVE-2022-50306", "CVE-2022-50323", "CVE-2022-50350", "CVE-2022-50390", "CVE-2022-50493", "CVE-2023-53171", "CVE-2023-53178", "CVE-2023-53215", "CVE-2023-53220", "CVE-2023-53221", "CVE-2023-53250", "CVE-2023-53280", "CVE-2023-53395", "CVE-2023-53401", "CVE-2023-53421", "CVE-2023-53480", "CVE-2024-56616", "CVE-2024-58239", "CVE-2025-21826", "CVE-2025-37765", "CVE-2025-38015", "CVE-2025-38035", "CVE-2025-38040", "CVE-2025-38079", "CVE-2025-38103", "CVE-2025-38112", "CVE-2025-38129", "CVE-2025-38146", "CVE-2025-38147", "CVE-2025-38174", "CVE-2025-38181", "CVE-2025-38207", "CVE-2025-38212", "CVE-2025-38264", "CVE-2025-38312", "CVE-2025-38332", "CVE-2025-38334", "CVE-2025-38393", "CVE-2025-38424", "CVE-2025-38465", "CVE-2025-38499", "CVE-2025-38515", "CVE-2025-38516", "CVE-2025-38539", "CVE-2025-38540", "CVE-2025-38553", "CVE-2025-38563", "CVE-2025-38565", "CVE-2025-38574", "CVE-2025-38584", "CVE-2025-38622", "CVE-2025-38632", "CVE-2025-38635", "CVE-2025-38668", "CVE-2025-38671", "CVE-2025-38680", "CVE-2025-38685", "CVE-2025-38693", "CVE-2025-38695", "CVE-2025-38701", "CVE-2025-38710", "CVE-2025-39681", "CVE-2025-39683", "CVE-2025-39689", "CVE-2025-39691", "CVE-2025-39742", "CVE-2025-39744", "CVE-2025-39749", "CVE-2025-39760", "CVE-2025-39782", "CVE-2025-39813", "CVE-2025-39829", "CVE-2025-39865", "CVE-2025-39866", "CVE-2025-39949", "CVE-2025-39953", "CVE-2025-39971", "CVE-2025-39973", "CVE-2025-39993");
  script_tag(name:"creation_date", value:"2025-12-11 12:41:26 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T05:45:42+0000");
  script_tag(name:"last_modification", value:"2025-12-12 05:45:42 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-26 17:57:27 +0000 (Wed, 26 Nov 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2483)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP11");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2483");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2483");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2483 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"scsi: qla2xxx: Fix warning message due to adisc being flushed(CVE-2022-49158)

scsi: qla2xxx: Implement ref count for SRB(CVE-2022-49159)

tcp: add accessors to read/set tp->snd_cwnd(CVE-2022-49325)

KVM: VMX: Do _all_ initialization before exposing /dev/kvm to userspace(CVE-2022-49932)

mmc: rtsx_pci: fix return value check of mmc_add_host()(CVE-2022-50267)

ext4: fix potential out of bound read in ext4_fc_replay_scan()(CVE-2022-50306)

net: do not sense pfmemalloc status in skb_append_pagefrags()(CVE-2022-50323)

scsi: target: iscsi: Fix a race condition between login_work and the login thread(CVE-2022-50350)

drm/ttm: fix undefined behavior in bit shift for TTM_TT_FLAG_PRIV_POPULATED(CVE-2022-50390)

scsi: qla2xxx: Fix crash when I/O abort times out(CVE-2022-50493)

vfio/type1: prevent underflow of locked_vm via exec()(CVE-2023-53171)

mm: fix zswap writeback race condition(CVE-2023-53178)

sched/fair: Don't balance task to its current running CPU(CVE-2023-53215)

media: az6007: Fix null-ptr-deref in az6007_i2c_xfer()(CVE-2023-53220)

bpf: Fix memleak due to fentry attach failure(CVE-2023-53221)

firmware: dmi-sysfs: Fix null-ptr-deref in dmi_sysfs_register_handle(CVE-2023-53250)

scsi: qla2xxx: Remove unused nvme_ls_waitq wait queue(CVE-2023-53280)

ACPICA: Add AML_NO_OPERAND_RESOLVE flag to Timer(CVE-2023-53395)

mm: kmem: fix a NULL pointer dereference in obj_stock_flush_required()(CVE-2023-53401)

blk-cgroup: Reinit blkg_iostat_set after clearing in blkcg_reset_stats()(CVE-2023-53421)

kobject: Add sanity check for kset->kobj.ktype in kset_register()(CVE-2023-53480)

drm/dp_mst: Fix MST sideband message body length check(CVE-2024-56616)

tls: stop recv() if initial process_rx_list gave us non-DATA(CVE-2024-58239)

netfilter: nf_tables: reject mismatching sum of field_len with set key length(CVE-2025-21826)

drm/nouveau: prime: fix ttm_bo_delayed_delete oops(CVE-2025-37765)

dmaengine: idxd: fix memory leak in error handling path of idxd_alloc(CVE-2025-38015)

nvmet-tcp: don't restore null sk_state_change(CVE-2025-38035)

serial: mctrl_gpio: split disable_ms into sync and no_sync APIs(CVE-2025-38040)

crypto: algif_hash - fix double free in hash_accept(CVE-2025-38079)

HID: usbhid: Eliminate recurrent out-of-bounds bug in usbhid_parse()(CVE-2025-38103)

net: Fix TOCTOU issue in sk_is_readable()(CVE-2025-38112)

page_pool: Fix use-after-free in page_pool_recycle_in_ring(CVE-2025-38129)

net: openvswitch: Fix the dead loop of MPLS parse(CVE-2025-38146)

calipso: Don't call calipso functions for AF_INET sk.(CVE-2025-38147)

thunderbolt: Do not double dequeue a configuration request(CVE-2025-38174)

calipso: Fix null-ptr-deref in calipso_req_{set,del}attr().(CVE-2025-38181)

mm: fix uprobe pte be overwritten when expanding vma(CVE-2025-38207)

ipc: fix to protect IPCS lookups using RCU(CVE-2025-38212)

nvme-tcp: sanitize request list handling(CVE-2025-38264)

fbdev: ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'kernel' package(s) on Huawei EulerOS V2.0SP11.");

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

if(release == "EULEROS-2.0SP11") {

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~60.18.0.50.h2056.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~60.18.0.50.h2056.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~60.18.0.50.h2056.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~60.18.0.50.h2056.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~60.18.0.50.h2056.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~60.18.0.50.h2056.eulerosv2r11", rls:"EULEROS-2.0SP11"))) {
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
