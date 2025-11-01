# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.856876");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2022-4806");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-05 23:52:15 +0000 (Thu, 05 Jan 2023)");
  script_tag(name:"creation_date", value:"2024-12-24 05:00:23 +0000 (Tue, 24 Dec 2024)");
  script_name("openSUSE: Security Advisory for gdb (SUSE-SU-2024:4414-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:4414-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/XADET6R2KJRSII5ZV36JUKWSLM6HXUVH");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb'
  package(s) announced via the SUSE-SU-2024:4414-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gdb fixes the following issues:

  Mention changes in GDB 14:

  * GDB now supports the AArch64 Scalable Matrix Extension 2 (SME2), which
      includes a new 512 bit lookup table register named ZT0.

  * The AArch64 'org.gnu.gdb.aarch64.pauth' Pointer Authentication feature
      string has been deprecated in favor of the 'org.gnu.gdb.aarch64.pauth_v2'
      feature string.

  * GDB now has some support for integer types larger than 64 bits.

  * Multi-target feature configuration. GDB now supports the individual
      configuration of remote targets' feature sets. Based on the current
      selection of a target, the commands 'set remote  name>-packet (onoffauto)'
      and 'show remote  name>-packet' can be used to configure a target's feature
      packet and to display its configuration, respectively.

  * GDB has initial built-in support for the Debugger Adapter Protocol.

  * For the break command, multiple uses of the 'thread' or 'task' keywords will
      now give an error instead of just using the thread or task id from the last
      instance of the keyword. E.g.: break foo thread 1 thread 2 will now give an
      error rather than using 'thread 2'.

  * For the watch command, multiple uses of the 'task' keyword will now give an
      error instead of just using the task id from the last instance of the
      keyword. E.g.: watch my_var task 1 task 2 will now give an error rather than
      using 'task 2'. The 'thread' keyword already gave an error when used
      multiple times with the watch command, this remains unchanged.

  * The 'set print elements' setting now helps when printing large arrays. If an
      array would otherwise exceed max-value-size, but 'print elements' is set
      such that the size of elem ...

  Description truncated. Please see the references for more information.");

  script_tag(name:"affected", value:"'gdb' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5, openSUSE Leap 15.6.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
