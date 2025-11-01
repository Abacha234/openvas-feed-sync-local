# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856256");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2020-36788", "CVE-2021-3743", "CVE-2021-39698", "CVE-2021-43056", "CVE-2021-47104", "CVE-2021-47192", "CVE-2021-47200", "CVE-2021-47220", "CVE-2021-47227", "CVE-2021-47228", "CVE-2021-47229", "CVE-2021-47230", "CVE-2021-47231", "CVE-2021-47235", "CVE-2021-47236", "CVE-2021-47237", "CVE-2021-47239", "CVE-2021-47240", "CVE-2021-47241", "CVE-2021-47246", "CVE-2021-47252", "CVE-2021-47253", "CVE-2021-47254", "CVE-2021-47255", "CVE-2021-47258", "CVE-2021-47259", "CVE-2021-47260", "CVE-2021-47261", "CVE-2021-47263", "CVE-2021-47265", "CVE-2021-47267", "CVE-2021-47269", "CVE-2021-47270", "CVE-2021-47274", "CVE-2021-47275", "CVE-2021-47276", "CVE-2021-47280", "CVE-2021-47281", "CVE-2021-47284", "CVE-2021-47285", "CVE-2021-47288", "CVE-2021-47289", "CVE-2021-47296", "CVE-2021-47301", "CVE-2021-47302", "CVE-2021-47305", "CVE-2021-47307", "CVE-2021-47308", "CVE-2021-47314", "CVE-2021-47315", "CVE-2021-47320", "CVE-2021-47321", "CVE-2021-47323", "CVE-2021-47324", "CVE-2021-47329", "CVE-2021-47330", "CVE-2021-47332", "CVE-2021-47333", "CVE-2021-47334", "CVE-2021-47337", "CVE-2021-47338", "CVE-2021-47340", "CVE-2021-47341", "CVE-2021-47343", "CVE-2021-47344", "CVE-2021-47347", "CVE-2021-47348", "CVE-2021-47350", "CVE-2021-47353", "CVE-2021-47354", "CVE-2021-47356", "CVE-2021-47369", "CVE-2021-47375", "CVE-2021-47378", "CVE-2021-47381", "CVE-2021-47382", "CVE-2021-47383", "CVE-2021-47387", "CVE-2021-47388", "CVE-2021-47391", "CVE-2021-47392", "CVE-2021-47393", "CVE-2021-47395", "CVE-2021-47396", "CVE-2021-47399", "CVE-2021-47402", "CVE-2021-47404", "CVE-2021-47405", "CVE-2021-47409", "CVE-2021-47413", "CVE-2021-47416", "CVE-2021-47422", "CVE-2021-47423", "CVE-2021-47424", "CVE-2021-47425", "CVE-2021-47426", "CVE-2021-47428", "CVE-2021-47431", "CVE-2021-47434", "CVE-2021-47435", "CVE-2021-47436", "CVE-2021-47441", "CVE-2021-47442", "CVE-2021-47443", "CVE-2021-47444", "CVE-2021-47445", "CVE-2021-47451", "CVE-2021-47456", "CVE-2021-47458", "CVE-2021-47460", "CVE-2021-47464", "CVE-2021-47465", "CVE-2021-47468", "CVE-2021-47473", "CVE-2021-47478", "CVE-2021-47480", "CVE-2021-47482", "CVE-2021-47483", "CVE-2021-47485", "CVE-2021-47493", "CVE-2021-47494", "CVE-2021-47495", "CVE-2021-47496", "CVE-2021-47497", "CVE-2021-47498", "CVE-2021-47499", "CVE-2021-47500", "CVE-2021-47501", "CVE-2021-47502", "CVE-2021-47503", "CVE-2021-47505", "CVE-2021-47506", "CVE-2021-47507", "CVE-2021-47509", "CVE-2021-47511", "CVE-2021-47512", "CVE-2021-47516", "CVE-2021-47518", "CVE-2021-47521", "CVE-2021-47522", "CVE-2021-47523", "CVE-2021-47527", "CVE-2021-47535", "CVE-2021-47536", "CVE-2021-47538", "CVE-2021-47540", "CVE-2021-47541", "CVE-2021-47542", "CVE-2021-47549", "CVE-2021-47557", "CVE-2021-47562", "CVE-2021-47563", "CVE-2021-47565", "CVE-2022-1195", "CVE-2022-20132", "CVE-2022-48636", "CVE-2022-48673", "CVE-2022-48704", "CVE-2022-48710", "CVE-2023-0160", "CVE-2023-1829", "CVE-2023-2176", "CVE-2023-4244", "CVE-2023-47233", "CVE-2023-52433", "CVE-2023-52581", "CVE-2023-52591", "CVE-2023-52654", "CVE-2023-52655", "CVE-2023-52686", "CVE-2023-52840", "CVE-2023-52871", "CVE-2023-52880", "CVE-2023-6531", "CVE-2024-26581", "CVE-2024-26643", "CVE-2024-26828", "CVE-2024-26921", "CVE-2024-26925", "CVE-2024-26929", "CVE-2024-26930", "CVE-2024-27398", "CVE-2024-27413", "CVE-2024-35811", "CVE-2024-35895", "CVE-2024-35914");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-05-23 19:10:49 +0000 (Thu, 23 May 2024)");
  script_tag(name:"creation_date", value:"2024-06-29 04:00:38 +0000 (Sat, 29 Jun 2024)");
  script_name("openSUSE: Security Advisory for the Linux Kernel (SUSE-SU-2024:2185-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:2185-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/OPYFUGAUWEI7NDCHEJYHZGMLITTV463A");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'the Linux Kernel'
  package(s) announced via the SUSE-SU-2024:2185-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The SUSE Linux Enterprise 15 SP3 kernel was updated to receive various security
  bugfixes.

  The following security bugs were fixed:

  * CVE-2021-47378: Destroy cm id before destroy qp to avoid use after free
      (bsc#1225201).

  * CVE-2021-47496: Fix flipped sign in tls_err_abort() calls (bsc#1225354)

  * CVE-2021-47402: Protect fl_walk() with rcu (bsc#1225301)

  * CVE-2022-48673: kABI workarounds for struct smc_link (bsc#1223934).

  * CVE-2023-52871: Handle a second device without data corruption (bsc#1225534)

  * CVE-2024-26828: Fix underflow in parse_server_interfaces() (bsc#1223084).

  * CVE-2021-47497: Fixed shift-out-of-bound (UBSAN) with byte size cells
      (bsc#1225355).

  * CVE-2024-27413: Fix incorrect allocation size (bsc#1224438).

  * CVE-2021-47383: Fiedx out-of-bound vmalloc access in imageblit
      (bsc#1225208).

  * CVE-2021-47511: Fixed negative period/buffer sizes (bsc#1225411).

  * CVE-2023-52840: Fix use after free in rmi_unregister_function()
      (bsc#1224928).

  * CVE-2021-47261: Fix initializing CQ fragments buffer (bsc#1224954)

  * CVE-2021-47254: Fix use-after-free in gfs2_glock_shrink_scan (bsc#1224888).

  * CVE-2024-27398: Fixed use-after-free bugs caused by sco_sock_timeout
      (bsc#1224174).

  * CVE-2024-26921: Preserve kabi for sk_buff (bsc#1223138).

  * CVE-2023-52655: Check packet for fixup for true limit (bsc#1217169).

  * CVE-2023-4244: Fixed a use-after-free in the nf_tables component, which
      could be exploited to achieve local privilege escalation (bsc#1215420).

  * CVE-2023-4244: Fixed a use-after-free in the nf_tables component, which
      could be exploited to achieve local privilege escalation (bsc#1215420).

  * CVE-2023-1829: Fixed a use-after-free vulnerability in the control index
      filter (tcindex) (bsc#1210335).

  * CVE-2023-52686: Fix a null pointer in opal_event_init() (bsc#1065729).

  The following non-security bugs were fixed:

  * af_unix: Do not use atomic ops for unix_sk(sk)->inflight (bsc#1223384).

  * af_unix: Replace BUG_ON() with WARN_ON_ONCE() (bsc#1223384).

  * btrfs: do not start relocation until in progress drops are done
      (bsc#1222251).

  * btrfs: do not start relocation until in progress drops are done
      (bsc#1222251).

  * cifs: add missing spinlock around tcon refcount (bsc#1213476).

  * cifs: avoid dup prefix path in dfs_get_automount_devname() (bsc#1213476).
    ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'the Linux Kernel' package(s) on openSUSE Leap 15.3.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
