# SPDX-FileCopyrightText: 2025 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.2.2025.2501");
  script_cve_id("CVE-2022-49124", "CVE-2022-49142", "CVE-2022-49157", "CVE-2022-49158", "CVE-2022-49159", "CVE-2022-49936", "CVE-2022-50251", "CVE-2022-50255", "CVE-2022-50266", "CVE-2022-50267", "CVE-2022-50280", "CVE-2022-50286", "CVE-2022-50306", "CVE-2022-50312", "CVE-2022-50313", "CVE-2022-50315", "CVE-2022-50318", "CVE-2022-50323", "CVE-2022-50328", "CVE-2022-50330", "CVE-2022-50344", "CVE-2022-50346", "CVE-2022-50350", "CVE-2022-50377", "CVE-2022-50382", "CVE-2022-50388", "CVE-2022-50389", "CVE-2022-50390", "CVE-2022-50394", "CVE-2022-50411", "CVE-2022-50425", "CVE-2022-50430", "CVE-2022-50440", "CVE-2022-50473", "CVE-2022-50485", "CVE-2022-50493", "CVE-2022-50497", "CVE-2022-50510", "CVE-2022-50553", "CVE-2023-53149", "CVE-2023-53167", "CVE-2023-53171", "CVE-2023-53176", "CVE-2023-53178", "CVE-2023-53215", "CVE-2023-53216", "CVE-2023-53220", "CVE-2023-53221", "CVE-2023-53242", "CVE-2023-53250", "CVE-2023-53259", "CVE-2023-53270", "CVE-2023-53280", "CVE-2023-53285", "CVE-2023-53288", "CVE-2023-53317", "CVE-2023-53318", "CVE-2023-53332", "CVE-2023-53368", "CVE-2023-53373", "CVE-2023-53375", "CVE-2023-53395", "CVE-2023-53401", "CVE-2023-53421", "CVE-2023-53437", "CVE-2023-53441", "CVE-2023-53450", "CVE-2023-53456", "CVE-2023-53480", "CVE-2023-53503", "CVE-2023-53506", "CVE-2023-53515", "CVE-2023-53521", "CVE-2023-53530", "CVE-2023-53560", "CVE-2023-53576", "CVE-2023-53577", "CVE-2023-53587", "CVE-2023-53611", "CVE-2023-53626", "CVE-2023-53661", "CVE-2023-53668", "CVE-2024-36357", "CVE-2024-56616", "CVE-2024-58239", "CVE-2025-38079", "CVE-2025-38174", "CVE-2025-38207", "CVE-2025-38332", "CVE-2025-38334", "CVE-2025-38494", "CVE-2025-38499", "CVE-2025-38502", "CVE-2025-38515", "CVE-2025-38516", "CVE-2025-38540", "CVE-2025-38553", "CVE-2025-38581", "CVE-2025-38584", "CVE-2025-38622", "CVE-2025-38668", "CVE-2025-38680", "CVE-2025-38685", "CVE-2025-38693", "CVE-2025-38695", "CVE-2025-38701", "CVE-2025-39681", "CVE-2025-39683", "CVE-2025-39689", "CVE-2025-39691", "CVE-2025-39724", "CVE-2025-39744", "CVE-2025-39749", "CVE-2025-39760", "CVE-2025-39782", "CVE-2025-39813", "CVE-2025-39829", "CVE-2025-39850", "CVE-2025-39851", "CVE-2025-39865", "CVE-2025-39866", "CVE-2025-39953", "CVE-2025-39967", "CVE-2025-39968", "CVE-2025-39971", "CVE-2025-39973");
  script_tag(name:"creation_date", value:"2025-12-11 12:41:26 +0000 (Thu, 11 Dec 2025)");
  script_version("2025-12-12T05:45:42+0000");
  script_tag(name:"last_modification", value:"2025-12-12 05:45:42 +0000 (Fri, 12 Dec 2025)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2025-11-26 17:57:27 +0000 (Wed, 26 Nov 2025)");

  script_name("Huawei EulerOS: Security Advisory for kernel (EulerOS-SA-2025-2501)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2025 Greenbone AG");
  script_family("Huawei EulerOS Local Security Checks");
  script_dependencies("gb_huawei_euleros_consolidation.nasl");
  script_mandatory_keys("ssh/login/euleros", "ssh/login/rpms", re:"ssh/login/release=EULEROS\-2\.0SP13\-X86_64");

  script_xref(name:"Advisory-ID", value:"EulerOS-SA-2025-2501");
  script_xref(name:"URL", value:"https://developer.huaweicloud.com/intl/en-us/euleros/securitydetail.html?secId=EulerOS-SA-2025-2501");

  script_tag(name:"summary", value:"The remote host is missing an update for the Huawei EulerOS 'kernel' package(s) announced via the EulerOS-SA-2025-2501 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"x86/mce: Work around an erratum on fast string copy instructions(CVE-2022-49124)

net: preserve skb_end_offset() in skb_unclone_keeptruesize()(CVE-2022-49142)

scsi: qla2xxx: Fix premature hw access after PCI error(CVE-2022-49157)

scsi: qla2xxx: Fix warning message due to adisc being flushed(CVE-2022-49158)

scsi: qla2xxx: Implement ref count for SRB(CVE-2022-49159)

USB: core: Prevent nested device-reset calls(CVE-2022-49936)

mmc: vub300: fix return value check of mmc_add_host()(CVE-2022-50251)

tracing: Fix reading strings from synthetic events(CVE-2022-50255)

kprobes: Fix check for probe enabled in kill_kprobe()(CVE-2022-50266)

mmc: rtsx_pci: fix return value check of mmc_add_host()(CVE-2022-50267)

pnode: terminate at peers of source(CVE-2022-50280)

ext4: fix delayed allocation bug in ext4_clu_mapped for bigalloc + inline(CVE-2022-50286)

ext4: fix potential out of bound read in ext4_fc_replay_scan()(CVE-2022-50306)

drivers: serial: jsm: fix some leaks in probe(CVE-2022-50312)

erofs: fix order >= MAX_ORDER warning due to crafted negative i_size(CVE-2022-50313)

ata: ahci: Match EM_MAX_SLOTS with SATA_PMP_MAX_PORTS(CVE-2022-50315)

perf/x86/intel/uncore: Fix reference count leak in hswep_has_limit_sbox()(CVE-2022-50318)

net: do not sense pfmemalloc status in skb_append_pagefrags()(CVE-2022-50323)

jbd2: fix potential use-after-free in jbd2_fc_wait_bufs(CVE-2022-50328)

crypto: cavium - prevent integer overflow loading firmware(CVE-2022-50330)

ext4: fix null-ptr-deref in ext4_write_info(CVE-2022-50344)

ext4: init quota for 'old.inode' in 'ext4_rename'(CVE-2022-50346)

scsi: target: iscsi: Fix a race condition between login_work and the login thread(CVE-2022-50350)

Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority.(CVE-2022-50377)

padata: Always leave BHs disabled when running ->parallel()(CVE-2022-50382)

nvme: fix multipath crash caused by flush request when blktrace is enabled(CVE-2022-50388)

tpm: tpm_crb: Add the missed acpi_put_table() to fix memory leak(CVE-2022-50389)

drm/ttm: fix undefined behavior in bit shift for TTM_TT_FLAG_PRIV_POPULATED(CVE-2022-50390)

i2c: ismt: Fix an out-of-bounds bug in ismt_access()(CVE-2022-50394)

ACPICA: Fix error code path in acpi_ds_call_control_method()(CVE-2022-50411)

x86/fpu: Fix copy_xstate_to_uabi() to copy init states correctly(CVE-2022-50425)

mmc: vub300: fix warning - do not call blocking ops when !TASK_RUNNING(CVE-2022-50430)

drm/vmwgfx: Validate the box size for the snooped cursor(CVE-2022-50440)

cpufreq: Init completion before kobject_init_and_add()(CVE-2022-50473)

ext4: add EXT4_IGET_BAD flag to prevent unexpected bad inode(CVE-2022-50485)

scsi: qla2xxx: Fix crash when I/O abort times out(CVE-2022-50493)

binfmt_misc: fix shift-out-of-bounds in check_special_flags(CVE-2022-50497)

perf/smmuv3: Fix hotplug callback leak in ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"bpftool", rpm:"bpftool~5.10.0~182.0.0.95.h3090.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel", rpm:"kernel~5.10.0~182.0.0.95.h3090.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-abi-stablelists", rpm:"kernel-abi-stablelists~5.10.0~182.0.0.95.h3090.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools", rpm:"kernel-tools~5.10.0~182.0.0.95.h3090.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"kernel-tools-libs", rpm:"kernel-tools-libs~5.10.0~182.0.0.95.h3090.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"python3-perf", rpm:"python3-perf~5.10.0~182.0.0.95.h3090.eulerosv2r13", rls:"EULEROS-2.0SP13-x86_64"))) {
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
