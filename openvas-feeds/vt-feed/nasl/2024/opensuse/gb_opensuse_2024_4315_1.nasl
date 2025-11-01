# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856850");
  script_version("2025-08-07T05:44:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2021-47594", "CVE-2022-48674", "CVE-2022-48979", "CVE-2022-48982", "CVE-2022-48983", "CVE-2022-48989", "CVE-2022-48990", "CVE-2023-52915", "CVE-2023-52917", "CVE-2023-52918", "CVE-2023-52921", "CVE-2023-52922", "CVE-2024-26782", "CVE-2024-26906", "CVE-2024-26953", "CVE-2024-35888", "CVE-2024-35937", "CVE-2024-35980", "CVE-2024-36484", "CVE-2024-36883", "CVE-2024-36886", "CVE-2024-36905", "CVE-2024-36953", "CVE-2024-36954", "CVE-2024-38577", "CVE-2024-38589", "CVE-2024-38615", "CVE-2024-40997", "CVE-2024-41016", "CVE-2024-41023", "CVE-2024-41049", "CVE-2024-42131", "CVE-2024-43817", "CVE-2024-43897", "CVE-2024-44932", "CVE-2024-44964", "CVE-2024-44995", "CVE-2024-46681", "CVE-2024-46800", "CVE-2024-46802", "CVE-2024-46804", "CVE-2024-46805", "CVE-2024-46807", "CVE-2024-46810", "CVE-2024-46812", "CVE-2024-46819", "CVE-2024-46821", "CVE-2024-46835", "CVE-2024-46842", "CVE-2024-46853", "CVE-2024-46859", "CVE-2024-46864", "CVE-2024-46871", "CVE-2024-47663", "CVE-2024-47665", "CVE-2024-47667", "CVE-2024-47669", "CVE-2024-47670", "CVE-2024-47671", "CVE-2024-47679", "CVE-2024-47682", "CVE-2024-47693", "CVE-2024-47695", "CVE-2024-47696", "CVE-2024-47697", "CVE-2024-47698", "CVE-2024-47699", "CVE-2024-47701", "CVE-2024-47709", "CVE-2024-47712", "CVE-2024-47713", "CVE-2024-47718", "CVE-2024-47723", "CVE-2024-47728", "CVE-2024-47735", "CVE-2024-47737", "CVE-2024-47742", "CVE-2024-47745", "CVE-2024-47749", "CVE-2024-47756", "CVE-2024-47757", "CVE-2024-49850", "CVE-2024-49851", "CVE-2024-49852", "CVE-2024-49855", "CVE-2024-49861", "CVE-2024-49863", "CVE-2024-49868", "CVE-2024-49870", "CVE-2024-49871", "CVE-2024-49875", "CVE-2024-49877", "CVE-2024-49879", "CVE-2024-49884", "CVE-2024-49891", "CVE-2024-49900", "CVE-2024-49902", "CVE-2024-49903", "CVE-2024-49905", "CVE-2024-49907", "CVE-2024-49908", "CVE-2024-49921", "CVE-2024-49924", "CVE-2024-49925", "CVE-2024-49934", "CVE-2024-49935", "CVE-2024-49938", "CVE-2024-49945", "CVE-2024-49947", "CVE-2024-49950", "CVE-2024-49957", "CVE-2024-49963", "CVE-2024-49965", "CVE-2024-49966", "CVE-2024-49968", "CVE-2024-49981", "CVE-2024-49983", "CVE-2024-49985", "CVE-2024-49989", "CVE-2024-50003", "CVE-2024-50007", "CVE-2024-50008", "CVE-2024-50009", "CVE-2024-50013", "CVE-2024-50017", "CVE-2024-50025", "CVE-2024-50026", "CVE-2024-50031", "CVE-2024-50044", "CVE-2024-50062", "CVE-2024-50067", "CVE-2024-50073", "CVE-2024-50074", "CVE-2024-50077", "CVE-2024-50078", "CVE-2024-50082", "CVE-2024-50089", "CVE-2024-50093", "CVE-2024-50095", "CVE-2024-50096", "CVE-2024-50098", "CVE-2024-50099", "CVE-2024-50103", "CVE-2024-50108", "CVE-2024-50110", "CVE-2024-50115", "CVE-2024-50116", "CVE-2024-50117", "CVE-2024-50124", "CVE-2024-50125", "CVE-2024-50127", "CVE-2024-50128", "CVE-2024-50131", "CVE-2024-50134", "CVE-2024-50135", "CVE-2024-50138", "CVE-2024-50141", "CVE-2024-50146", "CVE-2024-50147", "CVE-2024-50148", "CVE-2024-50150", "CVE-2024-50153", "CVE-2024-50154", "CVE-2024-50155", "CVE-2024-50156", "CVE-2024-50160", "CVE-2024-50167", "CVE-2024-50171", "CVE-2024-50179", "CVE-2024-50180", "CVE-2024-50182", "CVE-2024-50183", "CVE-2024-50184", "CVE-2024-50186", "CVE-2024-50187", "CVE-2024-50188", "CVE-2024-50189", "CVE-2024-50192", "CVE-2024-50194", "CVE-2024-50195", "CVE-2024-50196", "CVE-2024-50198", "CVE-2024-50201", "CVE-2024-50205", "CVE-2024-50208", "CVE-2024-50209", "CVE-2024-50215", "CVE-2024-50218", "CVE-2024-50229", "CVE-2024-50230", "CVE-2024-50232", "CVE-2024-50233", "CVE-2024-50234", "CVE-2024-50236", "CVE-2024-50237", "CVE-2024-50249", "CVE-2024-50255", "CVE-2024-50259", "CVE-2024-50261", "CVE-2024-50264", "CVE-2024-50265", "CVE-2024-50267", "CVE-2024-50268", "CVE-2024-50269", "CVE-2024-50271", "CVE-2024-50273", "CVE-2024-50274", "CVE-2024-50279", "CVE-2024-50282", "CVE-2024-50287", "CVE-2024-50289", "CVE-2024-50290", "CVE-2024-50292", "CVE-2024-50295", "CVE-2024-50298", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53052", "CVE-2024-53058", "CVE-2024-53059", "CVE-2024-53060", "CVE-2024-53061", "CVE-2024-53063", "CVE-2024-53066", "CVE-2024-53068", "CVE-2024-53079", "CVE-2024-53085", "CVE-2024-53088", "CVE-2024-53104", "CVE-2024-53110");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-14 18:24:41 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-12-14 05:05:56 +0000 (Sat, 14 Dec 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:4315-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4315-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/LQPWDP54GSTHYCV4CTCOE67D2ANVPPUW");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:4315-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP5 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2021-47594: mptcp: never allow the PM to close a listener subflow
      (bsc#1226560).

  * CVE-2022-48983: io_uring: Fix a null-ptr-deref in io_tctx_exit_cb()
      (bsc#1231959).

  * CVE-2024-26782: mptcp: fix double-free on socket dismantle (bsc#1222590).

  * CVE-2024-26906: Fixed invalid vsyscall page read for
      copy_from_kernel_nofault() (bsc#1223202).

  * CVE-2024-26953: net: esp: fix bad handling of pages from page_pool
      (bsc#1223656).

  * CVE-2024-35888: erspan: make sure erspan_base_hdr is present in skb->head
      (bsc#1224518).

  * CVE-2024-35937: wifi: cfg80211: check A-MSDU format more carefully
      (bsc#1224526).

  * CVE-2024-36883: net: fix out-of-bounds access in ops_init (bsc#1225725).

  * CVE-2024-36886: tipc: fix UAF in error path (bsc#1225730).

  * CVE-2024-36905: tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets
      (bsc#1225742).

  * CVE-2024-36954: tipc: fix a possible memleak in tipc_buf_append
      (bsc#1225764).

  * CVE-2024-38589: netrom: fix possible dead-lock in nr_rt_ioctl()
      (bsc#1226748).

  * CVE-2024-38615: cpufreq: exit() callback is optional (bsc#1226592).

  * CVE-2024-40997: cpufreq: amd-pstate: fix memory leak on CPU EPP exit
      (bsc#1227853).

  * CVE-2024-41023: sched/deadline: Fix task_struct reference leak
      (bsc#1228430).

  * CVE-2024-44932: idpf: fix UAFs when destroying the queues (bsc#1229808).

  * CVE-2024-44964: idpf: fix memory leaks and crashes while performing a soft
      reset (bsc#1230220).

  * CVE-2024-44995: net: hns3: fix a deadlock problem when config TC during
      resetting (bsc#1230231).

  * CVE-2024-46681: pktgen: use cpus_read_lock() in pg_net_init() (bsc#1230558).

  * CVE-2024-46800: sch/netem: fix use after free in netem_dequeue
      (bsc#1230827).

  * CVE-2024-47679: vfs: fix race between evice_inodes() and find_inode() input()
      (bsc#1231930).

  * CVE-2024-47701: ext4: avoid OOB when system.data xattr changes underneath
      the filesystem (bsc#1231920).

  * CVE-2024-47745: mm: call the security_mmap_file() LSM hook in
      remap_file_pages() (bsc#1232135).

  * CVE-2024-47757: nilfs2: fix potential oob read in nilfs_btree_check_delete()
      (bsc#1232187).

  * CVE-2024-49868: btrfs: fix a NULL pointer dereference when failed to start a
      new trasacntion (bsc#1232272).

  * CVE-2024-49921: drm/amd/display: Check null pointers before used
      (bsc#1232371).

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
