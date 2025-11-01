# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856848");
  script_version("2025-08-07T05:44:51+0000");
  script_xref(name:"CISA", value:"Known Exploited Vulnerability (KEV) catalog");
  script_xref(name:"URL", value:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog");
  script_cve_id("CVE-2023-52778", "CVE-2023-52920", "CVE-2023-52921", "CVE-2023-52922", "CVE-2024-26596", "CVE-2024-26703", "CVE-2024-26741", "CVE-2024-26782", "CVE-2024-26864", "CVE-2024-26953", "CVE-2024-27017", "CVE-2024-27407", "CVE-2024-35888", "CVE-2024-36000", "CVE-2024-36031", "CVE-2024-36484", "CVE-2024-36883", "CVE-2024-36886", "CVE-2024-36905", "CVE-2024-36920", "CVE-2024-36927", "CVE-2024-36954", "CVE-2024-36968", "CVE-2024-38589", "CVE-2024-40914", "CVE-2024-41023", "CVE-2024-42102", "CVE-2024-44995", "CVE-2024-46680", "CVE-2024-46681", "CVE-2024-46765", "CVE-2024-46788", "CVE-2024-46800", "CVE-2024-46828", "CVE-2024-46845", "CVE-2024-47666", "CVE-2024-47679", "CVE-2024-47701", "CVE-2024-47703", "CVE-2024-49852", "CVE-2024-49866", "CVE-2024-49868", "CVE-2024-49881", "CVE-2024-49883", "CVE-2024-49884", "CVE-2024-49894", "CVE-2024-49895", "CVE-2024-49897", "CVE-2024-49899", "CVE-2024-49901", "CVE-2024-49905", "CVE-2024-49908", "CVE-2024-49909", "CVE-2024-49911", "CVE-2024-49912", "CVE-2024-49913", "CVE-2024-49921", "CVE-2024-49922", "CVE-2024-49923", "CVE-2024-49925", "CVE-2024-49933", "CVE-2024-49934", "CVE-2024-49944", "CVE-2024-49945", "CVE-2024-49952", "CVE-2024-49959", "CVE-2024-49968", "CVE-2024-49975", "CVE-2024-49976", "CVE-2024-49983", "CVE-2024-49987", "CVE-2024-49989", "CVE-2024-50003", "CVE-2024-50004", "CVE-2024-50006", "CVE-2024-50009", "CVE-2024-50012", "CVE-2024-50014", "CVE-2024-50015", "CVE-2024-50026", "CVE-2024-50067", "CVE-2024-50080", "CVE-2024-50081", "CVE-2024-50082", "CVE-2024-50084", "CVE-2024-50087", "CVE-2024-50088", "CVE-2024-50089", "CVE-2024-50093", "CVE-2024-50095", "CVE-2024-50096", "CVE-2024-50098", "CVE-2024-50099", "CVE-2024-50100", "CVE-2024-50101", "CVE-2024-50102", "CVE-2024-50103", "CVE-2024-50108", "CVE-2024-50110", "CVE-2024-50115", "CVE-2024-50116", "CVE-2024-50117", "CVE-2024-50121", "CVE-2024-50124", "CVE-2024-50125", "CVE-2024-50127", "CVE-2024-50128", "CVE-2024-50130", "CVE-2024-50131", "CVE-2024-50134", "CVE-2024-50135", "CVE-2024-50136", "CVE-2024-50138", "CVE-2024-50139", "CVE-2024-50141", "CVE-2024-50145", "CVE-2024-50146", "CVE-2024-50147", "CVE-2024-50148", "CVE-2024-50150", "CVE-2024-50153", "CVE-2024-50154", "CVE-2024-50155", "CVE-2024-50156", "CVE-2024-50157", "CVE-2024-50158", "CVE-2024-50159", "CVE-2024-50160", "CVE-2024-50166", "CVE-2024-50167", "CVE-2024-50169", "CVE-2024-50171", "CVE-2024-50172", "CVE-2024-50175", "CVE-2024-50176", "CVE-2024-50177", "CVE-2024-50179", "CVE-2024-50180", "CVE-2024-50181", "CVE-2024-50182", "CVE-2024-50183", "CVE-2024-50184", "CVE-2024-50186", "CVE-2024-50187", "CVE-2024-50188", "CVE-2024-50189", "CVE-2024-50192", "CVE-2024-50194", "CVE-2024-50195", "CVE-2024-50196", "CVE-2024-50198", "CVE-2024-50200", "CVE-2024-50201", "CVE-2024-50205", "CVE-2024-50208", "CVE-2024-50209", "CVE-2024-50210", "CVE-2024-50215", "CVE-2024-50216", "CVE-2024-50218", "CVE-2024-50221", "CVE-2024-50224", "CVE-2024-50225", "CVE-2024-50228", "CVE-2024-50229", "CVE-2024-50230", "CVE-2024-50231", "CVE-2024-50232", "CVE-2024-50233", "CVE-2024-50234", "CVE-2024-50235", "CVE-2024-50236", "CVE-2024-50237", "CVE-2024-50240", "CVE-2024-50245", "CVE-2024-50246", "CVE-2024-50248", "CVE-2024-50249", "CVE-2024-50250", "CVE-2024-50252", "CVE-2024-50255", "CVE-2024-50257", "CVE-2024-50261", "CVE-2024-50264", "CVE-2024-50265", "CVE-2024-50267", "CVE-2024-50268", "CVE-2024-50269", "CVE-2024-50271", "CVE-2024-50273", "CVE-2024-50274", "CVE-2024-50275", "CVE-2024-50276", "CVE-2024-50279", "CVE-2024-50282", "CVE-2024-50287", "CVE-2024-50289", "CVE-2024-50290", "CVE-2024-50292", "CVE-2024-50295", "CVE-2024-50296", "CVE-2024-50298", "CVE-2024-50301", "CVE-2024-50302", "CVE-2024-53042", "CVE-2024-53043", "CVE-2024-53045", "CVE-2024-53048", "CVE-2024-53051", "CVE-2024-53052", "CVE-2024-53055", "CVE-2024-53056", "CVE-2024-53058", "CVE-2024-53059", "CVE-2024-53060", "CVE-2024-53061", "CVE-2024-53063", "CVE-2024-53066", "CVE-2024-53068", "CVE-2024-53072", "CVE-2024-53074", "CVE-2024-53076", "CVE-2024-53079", "CVE-2024-53081", "CVE-2024-53082", "CVE-2024-53085", "CVE-2024-53088", "CVE-2024-53093", "CVE-2024-53094", "CVE-2024-53095", "CVE-2024-53096", "CVE-2024-53100", "CVE-2024-53101", "CVE-2024-53104", "CVE-2024-53106", "CVE-2024-53108", "CVE-2024-53110", "CVE-2024-53112", "CVE-2024-53114", "CVE-2024-53121", "CVE-2024-53138");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-08-07 05:44:51 +0000 (Thu, 07 Aug 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-11-14 18:24:41 +0000 (Thu, 14 Nov 2024)");
  script_tag(name:"creation_date", value:"2024-12-14 05:02:59 +0000 (Sat, 14 Dec 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:4314-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4314-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/SARXL66CQHD5VSFG5PUBNBVBPVFUN4KT");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:4314-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP6 RT kernel was updated to receive various
  security bugfixes.

  The following security bugs were fixed:

  * CVE-2023-52778: mptcp: deal with large GSO size (bsc#1224948).

  * CVE-2023-52920: bpf: support non-r10 register spill/fill to/from stack in
      precision tracking (bsc#1232823).

  * CVE-2024-26596: net: dsa: fix netdev_priv() dereference before check on non-
      DSA netdevice events (bsc#1220355).

  * CVE-2024-26741: dccp/tcp: Unhash sk from ehash for tb2 alloc failure after
      check_estalblished() (bsc#1222587).

  * CVE-2024-26782: mptcp: fix double-free on socket dismantle (bsc#1222590).

  * CVE-2024-26953: net: esp: fix bad handling of pages from page_pool
      (bsc#1223656).

  * CVE-2024-27017: netfilter: nft_set_pipapo: walk over current view on netlink
      dump (bsc#1223733).

  * CVE-2024-35888: erspan: make sure erspan_base_hdr is present in skb->head
      (bsc#1224518).

  * CVE-2024-36000: mm/hugetlb: fix missing hugetlb_lock for resv uncharge
      (bsc#1224548).

  * CVE-2024-36883: net: fix out-of-bounds access in ops_init (bsc#1225725).

  * CVE-2024-36886: tipc: fix UAF in error path (bsc#1225730).

  * CVE-2024-36905: tcp: defer shutdown(SEND_SHUTDOWN) for TCP_SYN_RECV sockets
      (bsc#1225742).

  * CVE-2024-36927: ipv4: Fix uninit-value access in __ip_make_skb()
      (bsc#1225813).

  * CVE-2024-36954: tipc: fix a possible memleak in tipc_buf_append
      (bsc#1225764).

  * CVE-2024-36968: Bluetooth: L2CAP: Fix div-by-zero in l2cap_le_flowctl_init()
      (bsc#1226130).

  * CVE-2024-38589: netrom: fix possible dead-lock in nr_rt_ioctl()
      (bsc#1226748).

  * CVE-2024-40914: mm/huge_memory: do not unpoison huge_zero_folio
      (bsc#1227842).

  * CVE-2024-41023: sched/deadline: Fix task_struct reference leak
      (bsc#1228430).

  * CVE-2024-42102: Revert 'mm/writeback: fix possible divide-by-zero in
      wb_dirty_limits(), again' (bsc#1233132).

  * CVE-2024-44995: net: hns3: fix a deadlock problem when config TC during
      resetting (bsc#1230231).

  * CVE-2024-46680: Bluetooth: btnxpuart: Fix random crash seen while removing
      driver (bsc#1230557).

  * CVE-2024-46681: pktgen: use cpus_read_lock() in pg_net_init() (bsc#1230558).

  * CVE-2024-46765: ice: protect XDP configuration with a mutex (bsc#1230807).

  * CVE-2024-46800: sch/netem: fix use after free in netem_dequeue
      (bsc#1230827).

  * CVE-2024-47679: vfs: fix race between evice_inodes() and find_inode() input()
      (bsc#1231930).

  * CVE-2024-47701: ext4: avoid OOB when system.data xat ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
