# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.833522");
  script_version("2025-02-26T05:38:41+0000");
  script_cve_id("CVE-2023-5868", "CVE-2023-5869", "CVE-2023-5870");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2025-02-26 05:38:41 +0000 (Wed, 26 Feb 2025)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-10 18:15:07 +0000 (Sun, 10 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-03-04 07:19:13 +0000 (Mon, 04 Mar 2024)");
  script_name("openSUSE: Security Advisory for postgresql13 (SUSE-SU-2023:4455-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4455-1");
  script_xref(name:"URL", value:"https://lists.opensuse.org/archives/list/security-announce@lists.opensuse.org/thread/5BNZ32APPBA7OPW5LFMDXNNCCNWNVA7A");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postgresql13'
  package(s) announced via the SUSE-SU-2023:4455-1 advisory.
Note: This VT has been deprecated and replaced by a Notus scanner based one.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for postgresql13 fixes the following issues:

  Security issues fixed:

  * CVE-2023-5868: Fix handling of unknown-type arguments in DISTINCT 'any'
      aggregate functions. This error led to a text-type value being interpreted
      as an unknown-type value (that is, a zero-terminated string) at runtime.
      This could result in disclosure of server memory following the text value.
      (bsc#1216962)

  * CVE-2023-5869: Detect integer overflow while computing new array dimensions.
      When assigning new elements to array subscripts that are outside the current
      array bounds, an undetected integer overflow could occur in edge cases.
      Memory stomps that are potentially exploitable for arbitrary code execution
      are possible, and so is disclosure of server memory. (bsc#1216961)

  * CVE-2023-5870: Prevent the pg_signal_backend role from signalling background
      workers and autovacuum processes. The documentation says that
      pg_signal_backend cannot issue signals to superuser-owned processes. It was
      able to signal these background processes, though, because they advertise a
      role OID of zero. Treat that as indicating superuser ownership. The security
      implications of cancelling one of these process types are fairly small so
      far as the core code goes (we'll just start another one), but extensions
      might add background workers that are more vulnerable. Also ensure that the
      is_superuser parameter is set correctly in such processes. No specific
      security consequences are known for that oversight, but it might be
      significant for some extensions. (bsc#1216960)

  * Overhaul postgresql-README.SUSE and move it from the binary package to the
      noarch wrapper package.

  * Change the unix domain socket location from /var/run to /run.");

  script_tag(name:"affected", value:"'postgresql13' package(s) on openSUSE Leap 15.4, openSUSE Leap 15.5.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"deprecated", value:TRUE);

  exit(0);
}

exit(66);
